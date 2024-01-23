use color_eyre::eyre::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ergo_lib::ergotree_ir::chain::{
    address::{Address, AddressEncoder, NetworkPrefix},
    token::Token,
};
use ergo_lib::ergotree_ir::sigma_protocol::sigma_boolean::ProveDlog;
use ergo_lib::{ergo_chain_types::EcPoint, ergotree_ir::chain::ergo_box::BoxId};
use k256::ProjectivePoint;
use log::info;
use ratatui::{
    prelude::*,
    widgets::{block::*, *},
};
use spectrum_chain_connector::{
    ChainTxEvent, InboundValue, PendingDepositStatus, PendingExportStatus, PendingTxStatus, ProtoTermCell,
    SpectrumTx, SpectrumTxType, VaultBalance, VaultMsgOut, VaultResponse, VaultStatus,
};
use spectrum_crypto::digest::Blake2bDigest256;
use spectrum_ergo_connector::script::ExtraErgoData;
use spectrum_ergo_connector::AncillaryVaultInfo;
use spectrum_ledger::{
    cell::{AssetId, BoxDestination, CustomAsset, NativeCoin, Owner, PolicyId, SValue, TermCell},
    ChainId,
};
use spectrum_move::SerializedValue;
use std::collections::HashMap;
use tokio::sync::mpsc::UnboundedSender;
use tui_textarea::TextArea;

use super::{Component, Frame};
use crate::{
    action::Action,
    color_scheme::{BLUE, DARK_ORANGE, GREEN},
    config::Config,
    tui,
};
use crate::{color_scheme::PURPLE, event::Event};

#[derive(Default)]
pub struct Home<'a> {
    command_tx: Option<UnboundedSender<Action>>,
    config: Config,
    vault_manager_status: Option<VaultStatus<ExtraErgoData, BoxId>>,
    vault_utxo_details: Vec<VaultBalance<AncillaryVaultInfo>>,
    deposits: Vec<(InboundValue<BoxId>, DepositStatus)>,
    confirmed_transactions: Vec<SpectrumTx<BoxId, AncillaryVaultInfo>>,
    exported_values: Vec<TermCell>,
    tx_table_state: TableState,
    active_block: ActiveBlock,
    deposit_textarea: TextArea<'a>,
    withdrawal_textarea: TextArea<'a>,
    allowed_withdrawal_destinations: Vec<SerializedValue>,
}

enum DepositStatus {
    Unprocessed,
    Refunded,
    Processed,
}

impl<'a> Component for Home<'a> {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.command_tx = Some(tx);
        Ok(())
    }

    fn register_config_handler(&mut self, config: Config) -> Result<()> {
        self.config = config;
        Ok(())
    }

    fn handle_events(&mut self, event: Option<Event>) -> Result<Option<Action>> {
        let r = match event {
            Some(e) => match e {
                Event::Tui(tui_event) => match tui_event {
                    tui::Event::Key(key_event) => self.handle_key_events(key_event)?,
                    tui::Event::Mouse(mouse_event) => self.handle_mouse_events(mouse_event)?,
                    _ => None,
                },
                Event::VaultManager(VaultResponse { status, messages }) => {
                    self.vault_manager_status = Some(status);
                    for msg in messages {
                        match msg {
                            VaultMsgOut::TxEvent(ChainTxEvent::Applied(
                                ref tx @ SpectrumTx { ref tx_type, .. },
                            )) => {
                                self.confirmed_transactions.push(tx.clone());
                                match tx_type {
                                    SpectrumTxType::Deposit {
                                        imported_value,
                                        vault_balance,
                                    } => {
                                        for value in imported_value {
                                            let ix = self
                                                .deposits
                                                .iter()
                                                .position(|i| {
                                                    i.0.on_chain_identifier == value.on_chain_identifier
                                                })
                                                .unwrap();
                                            self.deposits[ix].1 = DepositStatus::Processed;
                                        }
                                        self.vault_utxo_details.push(vault_balance.clone());
                                        info!(
                                            target: "driver",
                                            "DEPOSIT CONFIRMED. BALANCE: {:?}, vault_utxo_details: {:?}",
                                            vault_balance,
                                            self.vault_utxo_details
                                        );
                                    }
                                    SpectrumTxType::Withdrawal {
                                        exported_value,
                                        vault_balance,
                                    } => {
                                        self.exported_values.extend(exported_value.iter().cloned());
                                        self.vault_utxo_details.push(vault_balance.clone());
                                        info!(
                                            target: "driver",
                                            "WITHDRAWAL CONFIRMED. BALANCE: {:?}, vault_utxo_details: {:?}",
                                            vault_balance,
                                            self.vault_utxo_details
                                        );
                                    }
                                    SpectrumTxType::NewUnprocessedDeposit(inbound_value) => {
                                        if !self.deposits.iter().any(|d| {
                                            d.0.on_chain_identifier == inbound_value.on_chain_identifier
                                        }) {
                                            self.deposits
                                                .push((inbound_value.clone(), DepositStatus::Unprocessed));
                                        }
                                    }
                                    SpectrumTxType::RefundedDeposit(inbound_value) => {
                                        let ix = self
                                            .deposits
                                            .iter()
                                            .position(|i| {
                                                i.0.on_chain_identifier == inbound_value.on_chain_identifier
                                            })
                                            .unwrap();
                                        self.deposits[ix].1 = DepositStatus::Refunded;
                                    }
                                }
                            }
                            VaultMsgOut::TxEvent(ChainTxEvent::Unapplied(ref tx)) => {
                                // Note: it's assumed that TXs are unapplied in reverse chronological order.
                                let removed_tx = self.confirmed_transactions.pop().unwrap();
                                assert_eq!(removed_tx, *tx);
                                match removed_tx.tx_type {
                                    SpectrumTxType::Deposit {
                                        imported_value,
                                        vault_balance,
                                    } => {
                                        for value in imported_value {
                                            let ix = self
                                                .deposits
                                                .iter()
                                                .position(|i| {
                                                    i.0.on_chain_identifier == value.on_chain_identifier
                                                })
                                                .unwrap();
                                            self.deposits[ix].1 = DepositStatus::Unprocessed;

                                            // Rollback vault UTxO
                                            let removed = self.vault_utxo_details.pop().unwrap();
                                            assert_eq!(removed, vault_balance);
                                        }
                                    }
                                    SpectrumTxType::Withdrawal {
                                        exported_value,
                                        vault_balance,
                                    } => {
                                        for value in exported_value {
                                            let ix = self
                                                .exported_values
                                                .iter()
                                                .position(|term_cell| value == *term_cell)
                                                .unwrap();
                                            let removed = self.exported_values.swap_remove(ix);
                                            assert_eq!(value, removed);
                                        }

                                        // Rollback vault UTxO
                                        let removed = self.vault_utxo_details.pop().unwrap();
                                        assert_eq!(removed, vault_balance);
                                    }
                                    SpectrumTxType::NewUnprocessedDeposit(inbound_value) => {
                                        let ix = self
                                            .deposits
                                            .iter()
                                            .position(|i| {
                                                i.0.on_chain_identifier == inbound_value.on_chain_identifier
                                            })
                                            .unwrap();
                                        self.deposits.swap_remove(ix);
                                    }
                                    SpectrumTxType::RefundedDeposit(inbound_value) => {
                                        // If we rollback a deposit refund, it becomes unprocessed again.
                                        let ix = self
                                            .deposits
                                            .iter()
                                            .position(|i| {
                                                i.0.on_chain_identifier == inbound_value.on_chain_identifier
                                            })
                                            .unwrap();
                                        self.deposits[ix].1 = DepositStatus::Unprocessed;
                                    }
                                }
                            }
                            VaultMsgOut::ProposedTxsToNotarize(_) => {}
                            VaultMsgOut::GenesisVaultUtxo(s) => {
                                //self.vault_utxo_details = Some(s);
                            }
                        }
                    }
                    None
                }
            },
            _ => None,
        };
        Ok(r)
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        match action {
            Action::NextBlock => {
                self.active_block = self.active_block.next();
            }
            Action::EnterKey(e) => {
                match e.code {
                    KeyCode::Char(c) => {
                        match c {
                            'k' => {
                                match self.active_block {
                                    ActiveBlock::Transactions => {
                                        let num_table_txs = self.num_deposits_and_withdrawals();
                                        if let Some(ix) = self.tx_table_state.selected() {
                                            if ix == 0 {
                                                self.tx_table_state.select(Some(num_table_txs - 1));
                                            } else {
                                                self.tx_table_state.select(Some(ix - 1));
                                            }
                                        } else {
                                            self.tx_table_state.select(Some(0));
                                        }
                                    }
                                    ActiveBlock::MakeDeposits => {
                                        // Pass through to text-area
                                        self.deposit_textarea.input(e);
                                    }
                                    ActiveBlock::MakeWithdrawals => {
                                        // Pass through to text-area
                                        self.withdrawal_textarea.input(e);
                                    }
                                    _ => (),
                                }
                            }
                            'j' => {
                                match self.active_block {
                                    ActiveBlock::Transactions => {
                                        let num_table_txs = self.num_deposits_and_withdrawals();
                                        if let Some(ix) = self.tx_table_state.selected() {
                                            if ix == num_table_txs - 1 {
                                                self.tx_table_state.select(Some(0));
                                            } else {
                                                self.tx_table_state.select(Some(ix + 1));
                                            }
                                        } else {
                                            self.tx_table_state.select(Some(0));
                                        }
                                    }
                                    ActiveBlock::MakeDeposits => {
                                        // Pass through to text-area
                                        self.deposit_textarea.input(e);
                                    }
                                    ActiveBlock::MakeWithdrawals => {
                                        // Pass through to text-area
                                        self.withdrawal_textarea.input(e);
                                    }
                                    _ => (),
                                }
                            }
                            'q' => {
                                if !matches!(
                                    self.active_block,
                                    ActiveBlock::MakeDeposits | ActiveBlock::MakeWithdrawals
                                ) {
                                    return Ok(Some(Action::Quit));
                                } else {
                                    // Pass through to text-area in MakeDeposits
                                    self.deposit_textarea.input(e);
                                }
                            }
                            _ => match self.active_block {
                                ActiveBlock::MakeDeposits => {
                                    self.deposit_textarea.input(e);
                                }
                                ActiveBlock::MakeWithdrawals => {
                                    self.withdrawal_textarea.input(e);
                                }
                                _ => (),
                            },
                        }
                    }
                    KeyCode::Backspace => match self.active_block {
                        ActiveBlock::MakeDeposits => {
                            self.deposit_textarea
                                .input(tui_textarea::Input::from(KeyEvent::from(KeyCode::Backspace)));
                        }
                        ActiveBlock::MakeWithdrawals => {
                            self.withdrawal_textarea
                                .input(tui_textarea::Input::from(KeyEvent::from(KeyCode::Backspace)));
                        }
                        _ => (),
                    },
                    KeyCode::Enter => match self.active_block {
                        ActiveBlock::MakeDeposits => {
                            if let Some(s) = self.deposit_textarea.lines().first() {
                                if s.trim() == "deposit" {
                                    return Ok(Some(Action::RequestDepositProcessing));
                                }
                            }
                        }
                        ActiveBlock::MakeWithdrawals => {
                            if let Some(s) = self.withdrawal_textarea.lines().first() {
                                if s.trim() == "withdrawal" {
                                    let nano_ergs =
                                        u64::from(self.vault_utxo_details.last().unwrap().value.native) / 100;
                                    let term_cells = self
                                        .allowed_withdrawal_destinations
                                        .iter()
                                        .map(|addr| proto_term_cell(nano_ergs, vec![], addr.clone()))
                                        .collect();
                                    return Ok(Some(Action::RequestWithdrawal(term_cells)));
                                }
                            }
                        }
                        _ => (),
                    },
                    _ => {}
                }
            }
            _ => {}
        }
        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, _area: Rect) -> Result<()> {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Ratio(1, 5),
                Constraint::Ratio(3, 5),
                Constraint::Ratio(1, 5),
            ])
            .split(f.size());

        self.render_main_block(f, rows[0]);

        // This row will contain the 'Transactions' and 'Desposits' blocks.
        let second_row = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rows[1]);

        self.render_tx_block(f, second_row[0]);
        self.render_deposits_block(f, second_row[1]);

        let main_row = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rows[2]);

        self.render_make_deposits_block(f, main_row[0]);
        self.render_make_withdrawals_block(f, main_row[1]);

        Ok(())
    }
}

impl<'a> Home<'a> {
    pub fn new(allowed_withdrawal_destinations: Vec<SerializedValue>) -> Self {
        Home {
            allowed_withdrawal_destinations,
            ..Default::default()
        }
    }

    fn block_border_style(&self, block: ActiveBlock) -> Style {
        if self.active_block == block {
            Style::default().fg(PURPLE).add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        }
    }

    fn render_main_block(&mut self, f: &mut Frame<'_>, row: Rect) {
        let mut vault_lines = render_vault_utxo_details(self.vault_utxo_details.last());
        let status_line = render_status_line(&self.vault_manager_status);
        vault_lines.push(status_line);

        f.render_widget(
            Paragraph::new(vault_lines).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Title::from(" Spectrum Network Vault "))
                    .style(self.block_border_style(ActiveBlock::Main))
                    .border_type(BorderType::Rounded)
                    .padding(Padding::uniform(1)),
            ),
            row,
        );
    }

    fn render_tx_block(&mut self, f: &mut Frame<'_>, rect: Rect) {
        let mut tx_rows: Vec<_> = self
            .confirmed_transactions
            .iter()
            .filter_map(|t| {
                let tx_type = match t.tx_type {
                    SpectrumTxType::Deposit { .. } => Cell::from("DEPOSIT").style(Style::reset()),
                    SpectrumTxType::Withdrawal { .. } => Cell::from("WITHDRAWAL").style(Style::reset()),
                    _ => return None,
                };

                let mut cells = vec![tx_type];
                let height_cell =
                    Cell::from(u64::from(t.progress_point.point).to_string()).style(Style::reset());
                let status_cell = Cell::from("CONFIRMED").style(Style::reset().fg(GREEN));

                match &t.tx_type {
                    SpectrumTxType::Deposit {
                        imported_value,
                        vault_balance,
                    } => {
                        let ValueSummary { ergs, .. } = summarise_inbound_value(imported_value);
                        let tx_id_cell = Cell::from(vault_balance.on_chain_characteristics.tx_id.to_string())
                            .style(Style::reset());
                        cells.extend([tx_id_cell, ergs, height_cell, status_cell]);
                    }
                    SpectrumTxType::Withdrawal {
                        exported_value,
                        vault_balance,
                    } => {
                        let ValueSummary { ergs, .. } = summarise_term_cells(exported_value);
                        let tx_id_cell = Cell::from(vault_balance.on_chain_characteristics.tx_id.to_string())
                            .style(Style::reset());
                        cells.extend([tx_id_cell, ergs, height_cell, status_cell]);
                    }
                    _ => return None,
                }
                Some(Row::new(cells))
            })
            .collect();

        // Check if there's a pending TX
        if let Some(status) = &self.vault_manager_status {
            match status {
                VaultStatus::Synced {
                    current_progress_point,
                    pending_tx_status: Some(tx_status),
                }
                | VaultStatus::Syncing {
                    current_progress_point,
                    pending_tx_status: Some(tx_status),
                    ..
                } => {
                    let height_cell =
                        Cell::from(u64::from(current_progress_point.point).to_string()).style(Style::reset());
                    let tx_id_cell = Cell::from("...".to_string()).style(Style::reset());
                    match tx_status {
                        PendingTxStatus::Export(e) => {
                            let PendingExportStatus { identifier, .. } = e;
                            let ValueSummary { ergs, .. } = summarise_term_cells(&identifier.value_to_export);
                            let status_cell = Cell::from("PENDING").style(Style::reset().fg(DARK_ORANGE));
                            let tx_type = Cell::from("WITHDRAWAL").style(Style::reset());

                            tx_rows.push(Row::new(vec![
                                tx_type,
                                tx_id_cell,
                                ergs,
                                height_cell,
                                status_cell,
                            ]));
                        }
                        PendingTxStatus::Deposit(d) => {
                            let PendingDepositStatus { identifier, .. } = d;
                            let ValueSummary { ergs, .. } = summarise_inbound_value(identifier);
                            let status_cell = Cell::from("PENDING").style(Style::reset().fg(DARK_ORANGE));
                            let tx_type = Cell::from("DEPOSIT").style(Style::reset());

                            tx_rows.push(Row::new(vec![
                                tx_type,
                                tx_id_cell,
                                ergs,
                                height_cell,
                                status_cell,
                            ]));
                        }
                    }
                }
                _ => (),
            }
        }

        tx_rows.reverse();

        let widths = [
            Constraint::Length(10),
            Constraint::Min(10),
            Constraint::Length(7),
            Constraint::Length(9),
            Constraint::Length(9),
        ];

        let table = Table::new(tx_rows, widths)
            .column_spacing(2)
            .header(
                Row::new(vec!["Type", "TX ID", "Ergs", "Height ▼", "Status"])
                    .style(Style::reset().add_modifier(Modifier::BOLD)),
            )
            .highlight_style(Style::reset().bg(PURPLE))
            .highlight_symbol("> ");

        f.render_stateful_widget(
            table.block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Title::from(" Transactions "))
                    .style(self.block_border_style(ActiveBlock::Transactions))
                    .border_type(BorderType::Rounded)
                    .padding(Padding::uniform(1)),
            ),
            rect,
            &mut self.tx_table_state,
        );
    }

    fn render_deposits_block(&mut self, f: &mut Frame<'_>, rect: Rect) {
        let widths = [
            Constraint::Length(10),
            Constraint::Length(9),
            Constraint::Length(13),
        ];

        let deposit_rows: Vec<_> = self
            .deposits
            .iter()
            .map(|(inbound_value, status)| {
                let Owner::ProveDlog(pk) = inbound_value.owner else {
                    panic!("Script Hash owners of deposits not supported");
                };

                let projective_point = ProjectivePoint::from(pk.as_affine());
                let prove_dlog = ProveDlog::from(EcPoint::from(projective_point));
                let owner_str = AddressEncoder::encode_address_as_string(
                    NetworkPrefix::Mainnet,
                    &Address::P2Pk(prove_dlog),
                );
                let status_cell = match status {
                    DepositStatus::Unprocessed => {
                        Cell::from("UNPROCESSED").style(Style::reset().fg(DARK_ORANGE))
                    }
                    DepositStatus::Refunded => Cell::from("REFUNDED").style(Style::reset().fg(BLUE)),
                    DepositStatus::Processed => Cell::from("PROCESSED").style(Style::reset().fg(GREEN)),
                };
                Row::new(vec![
                    Cell::from(owner_str.to_string()).style(Style::reset()),
                    Cell::from(format!(
                        "{:?}",
                        (u64::from(inbound_value.value.native) as f64 / 1000000000.0)
                    ))
                    .style(Style::reset()),
                    status_cell,
                ])
            })
            .collect();
        let deposit_cell_table = Table::new(deposit_rows, widths)
            .column_spacing(2)
            .header(
                Row::new(vec!["From", "Ergs", "Status"]).style(Style::reset().add_modifier(Modifier::BOLD)),
            )
            .highlight_symbol(">");

        f.render_widget(
            deposit_cell_table.block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Title::from(" Deposits "))
                    .style(self.block_border_style(ActiveBlock::Deposits))
                    .border_type(BorderType::Rounded)
                    .padding(Padding::uniform(1)),
            ),
            rect,
        );
    }

    fn render_make_deposits_block(&mut self, f: &mut Frame<'_>, rect: Rect) {
        let outer_block = Block::new()
            .borders(Borders::ALL)
            .title(Title::from(" Process deposits "))
            .border_type(BorderType::Rounded)
            .style(self.block_border_style(ActiveBlock::MakeDeposits))
            .padding(Padding::uniform(1));

        let inner = outer_block.inner(rect);

        f.render_widget(outer_block, rect);

        let rows = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
            .split(inner);

        f.render_widget(
            Paragraph::new("Type 'deposit' then press ENTER to initiate Spectrum-Network deposit TX")
                .style(Style::reset())
                .wrap(Wrap { trim: true }),
            rows[0],
        );

        let textarea_border_style = if let Some(s) = self.deposit_textarea.lines().first() {
            if s.trim() == "deposit" {
                Style::reset().fg(GREEN)
            } else {
                Style::reset()
            }
        } else {
            Style::reset()
        };

        self.deposit_textarea.set_style(Style::reset());
        self.deposit_textarea.set_block(
            Block::default()
                .borders(Borders::ALL)
                .style(textarea_border_style),
        );

        f.render_widget(self.deposit_textarea.widget(), rows[1]);
    }

    fn render_make_withdrawals_block(&mut self, f: &mut Frame<'_>, rect: Rect) {
        let outer_block = Block::new()
            .borders(Borders::ALL)
            .title(Title::from(" Make withdrawals  "))
            .border_type(BorderType::Rounded)
            .style(self.block_border_style(ActiveBlock::MakeWithdrawals))
            .padding(Padding::uniform(1));

        let inner = outer_block.inner(rect);

        f.render_widget(outer_block, rect);

        let rows = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
            .split(inner);

        f.render_widget(
            Paragraph::new("Type 'withdrawal' then press ENTER to initiate Spectrum-Network withdrawal TX (1% of vault value to each white listed address)")
                .style(Style::reset())
                .wrap(Wrap { trim: true }),
            rows[0],
        );

        let textarea_border_style = if let Some(s) = self.withdrawal_textarea.lines().first() {
            if s.trim() == "withdrawal" {
                Style::reset().fg(GREEN)
            } else {
                Style::reset()
            }
        } else {
            Style::reset()
        };

        self.withdrawal_textarea.set_style(Style::reset());
        self.withdrawal_textarea.set_block(
            Block::default()
                .borders(Borders::ALL)
                .style(textarea_border_style),
        );

        f.render_widget(self.withdrawal_textarea.widget(), rows[1]);
    }

    fn num_deposits_and_withdrawals(&self) -> usize {
        self.confirmed_transactions
            .iter()
            .filter(|t| {
                matches!(
                    t.tx_type,
                    SpectrumTxType::Deposit { .. } | SpectrumTxType::Withdrawal { .. }
                )
            })
            .count()
    }
}

fn render_status_line(vault_manager_status: &Option<VaultStatus<ExtraErgoData, BoxId>>) -> Line {
    let mut spans = vec![Span::styled(
        "Connector status: ",
        Style::reset().add_modifier(Modifier::BOLD),
    )];

    match vault_manager_status {
        Some(VaultStatus::Synced {
            current_progress_point,
            ..
        }) => {
            spans.push(Span::styled("Sync'ed", Style::reset().fg(GREEN)));
            spans.push(Span::styled(
                format!(", @ block height: {}", u64::from(current_progress_point.point)),
                Style::reset(),
            ));
        }
        Some(VaultStatus::Syncing {
            current_progress_point,
            num_points_remaining,
            ..
        }) => {
            let extra_spans = vec![
                Span::styled("Syncing", Style::reset().fg(DARK_ORANGE)),
                Span::styled(
                    format!(", @ block height: {}", u64::from(current_progress_point.point)),
                    Style::reset(),
                ),
                Span::styled(
                    format!(", # blocks remaining: {}", num_points_remaining),
                    Style::reset(),
                ),
            ];
            spans.extend(extra_spans);
        }
        None => {
            spans.push(Span::styled("Unknown", Style::reset()));
        }
    };
    Line::from(spans)
}

fn render_vault_utxo_details(value: Option<&VaultBalance<AncillaryVaultInfo>>) -> Vec<Line> {
    let spans = vec![Span::styled(
        "Vault UTxO: ",
        Style::reset().add_modifier(Modifier::BOLD),
    )];

    let vault_heading = Line::from(spans);

    let content = if let Some(value) = value {
        format!(
            "  Value: {} ergs",
            (u64::from(value.value.native) as f64 / 1000000000.0)
        )
    } else {
        String::from("  UNKNOWN")
    };

    let spans = vec![Span::styled(content, Style::reset())];
    let value_line = Line::from(spans);

    vec![vault_heading, value_line]
}

pub fn proto_term_cell(nano_ergs: u64, tokens: Vec<Token>, address: SerializedValue) -> ProtoTermCell {
    let dst = BoxDestination {
        target: ChainId::from(0),
        address,
        inputs: None,
    };
    let mut assets = HashMap::new();
    let asset_map: HashMap<AssetId, CustomAsset> = tokens
        .into_iter()
        .map(|t| {
            let asset_id = AssetId::from(Blake2bDigest256::try_from(<Vec<u8>>::from(t.token_id)).unwrap());
            let custom_asset = CustomAsset::from(*t.amount.as_u64());
            (asset_id, custom_asset)
        })
        .collect();
    assets.insert(PolicyId::from(Blake2bDigest256::zero()), asset_map);
    ProtoTermCell {
        value: SValue {
            native: NativeCoin::from(nano_ergs),
            assets,
        },
        dst,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ActiveBlock {
    #[default]
    Main,
    Transactions,
    Deposits,
    MakeWithdrawals,
    MakeDeposits,
}

impl ActiveBlock {
    fn next(self) -> Self {
        match self {
            ActiveBlock::Main => ActiveBlock::Transactions,
            ActiveBlock::Transactions => ActiveBlock::Deposits,
            ActiveBlock::Deposits => ActiveBlock::MakeDeposits,
            ActiveBlock::MakeDeposits => ActiveBlock::MakeWithdrawals,
            ActiveBlock::MakeWithdrawals => ActiveBlock::Main,
        }
    }
}

fn summarise_inbound_value(values: &Vec<InboundValue<BoxId>>) -> ValueSummary {
    let mut ergs = 0.0;
    let mut total_num_tokens = 0;
    let mut token_qty = 0;
    let policy_id = PolicyId::from(Blake2bDigest256::zero());
    for inbound_value in values {
        ergs += u64::from(inbound_value.value.native) as f64 / 1000000000.0;
        if let Some(tokens) = inbound_value.value.assets.get(&policy_id) {
            total_num_tokens += tokens.len();
            token_qty += tokens.values().fold(0, |acc, t| acc + u64::from(*t));
        }
    }
    let total_num_tokens = Cell::from(total_num_tokens.to_string()).style(Style::reset());
    let total_qty_tokens = Cell::from(token_qty.to_string()).style(Style::reset());
    let ergs = Cell::from(format!("{:.5}", ergs)).style(Style::reset());

    ValueSummary {
        ergs,
        total_num_tokens,
        total_qty_tokens,
    }
}

fn summarise_term_cells(values: &Vec<TermCell>) -> ValueSummary {
    let mut ergs = 0.0;
    let mut total_num_tokens = 0;
    let mut token_qty = 0;
    let policy_id = PolicyId::from(Blake2bDigest256::zero());

    for cell in values {
        ergs += u64::from(cell.value.native) as f64 / 1000000000.0;
        if let Some(tokens) = cell.value.assets.get(&policy_id) {
            total_num_tokens += tokens.len();
            token_qty += tokens.values().fold(0, |acc, t| acc + u64::from(*t));
        }
    }
    let total_num_tokens = Cell::from(total_num_tokens.to_string()).style(Style::reset());
    let total_qty_tokens = Cell::from(token_qty.to_string()).style(Style::reset());
    let ergs = Cell::from(format!("{:.5}", ergs)).style(Style::reset());

    ValueSummary {
        ergs,
        total_num_tokens,
        total_qty_tokens,
    }
}

struct ValueSummary<'a> {
    ergs: Cell<'a>,
    total_num_tokens: Cell<'a>,
    total_qty_tokens: Cell<'a>,
}

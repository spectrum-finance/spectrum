use color_eyre::{eyre::Result, owo_colors::OwoColorize};
use crossterm::{
    event::{KeyCode, KeyEvent},
    style::Stylize,
};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use ratatui::{
    prelude::*,
    widgets::{block::*, *},
};
use serde::{Deserialize, Serialize};
use spectrum_chain_connector::{VaultResponse, VaultStatus};
use spectrum_ergo_connector::rocksdb::vault_boxes::ErgoNotarizationBounds;
use spectrum_ergo_connector::script::ExtraErgoData;
use std::{collections::HashMap, time::Duration};
use tokio::sync::mpsc::UnboundedSender;

use super::{Component, Frame};
use crate::event::Event;
use crate::{
    action::Action,
    config::{Config, KeyBindings},
    tui,
};

#[derive(Default)]
pub struct Home {
    command_tx: Option<UnboundedSender<Action>>,
    config: Config,
    vault_manager_status: Option<VaultStatus<ExtraErgoData>>,
}

impl Home {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Component for Home {
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
                    None
                }
            },
            _ => None,
        };
        Ok(r)
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        match action {
            Action::Tick => {}
            _ => {}
        }
        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Ratio(1, 5),
                Constraint::Ratio(3, 5),
                Constraint::Ratio(1, 5),
            ])
            .split(f.size());

        let status_line = render_status_line(&self.vault_manager_status);

        f.render_widget(
            Paragraph::new(status_line).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Title::from(" Spectrum Network Vault "))
                    .border_type(BorderType::Rounded)
                    .padding(Padding::uniform(1)),
            ),
            rows[0],
        );

        let second_row = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(50),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
            ])
            .split(rows[1]);

        let mut tx_rows = vec![Row::new(vec![
            Cell::from("WITHDRAWAL"),
            Cell::from("0E2DC..."),
            Cell::from("20.3567"),
            Cell::from("10"),
            Cell::from("400"),
            Cell::from("1158866"),
            Cell::from("PENDING").style(Style::default().fg(Color::Yellow)),
        ])];

        tx_rows.extend(gen_tx_rows());

        let widths = [
            Constraint::Length(15),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(13),
            Constraint::Length(13),
            Constraint::Length(10),
            Constraint::Length(10),
        ];

        let table = Table::new(tx_rows, &widths)
            .column_spacing(1)
            .header(
                Row::new(vec![
                    "Type",
                    "TX ID",
                    "Ergs",
                    "# Token IDs",
                    "Qty tokens",
                    "Height",
                    "Status",
                ])
                .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .highlight_symbol(">");

        f.render_widget(
            table.block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Title::from(" Transactions "))
                    .border_type(BorderType::Rounded)
                    .padding(Padding::uniform(1)),
            ),
            second_row[0],
        );

        let active_cell_rows = [
            Row::new(vec![
                Cell::from("0B4F3..."),
                Cell::from("34.4"),
                Cell::from("..."),
            ]),
            Row::new(vec![
                Cell::from("6C78D..."),
                Cell::from("16.143"),
                Cell::from("..."),
            ]),
        ];

        let widths = [
            Constraint::Length(10),
            Constraint::Length(15),
            Constraint::Length(10),
        ];

        let active_cell_table = Table::new(gen_cells(), &widths)
            .column_spacing(1)
            .header(
                Row::new(vec!["Owner", "Native value", "Assets"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .highlight_symbol(">");

        f.render_widget(
            active_cell_table.block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Title::from(" Active cells "))
                    .border_type(BorderType::Rounded)
                    .padding(Padding::uniform(1)),
            ),
            second_row[1],
        );

        let deposit_rows = [
            Row::new(vec![
                Cell::from("2B834..."),
                Cell::from("34.4"),
                Cell::from("..."),
            ]),
            Row::new(vec![
                Cell::from("1BCC9..."),
                Cell::from("16.143"),
                Cell::from("..."),
            ]),
            Row::new(vec![
                Cell::from("FFA14..."),
                Cell::from("27.9"),
                Cell::from("..."),
            ]),
            Row::new(vec![Cell::from("C16DB..."), Cell::from("8.5"), Cell::from("...")]),
            Row::new(vec![
                Cell::from("9E24D..."),
                Cell::from("15.2"),
                Cell::from("..."),
            ]),
            Row::new(vec![
                Cell::from("EF1A2..."),
                Cell::from("22.7"),
                Cell::from("..."),
            ]),
            Row::new(vec![
                Cell::from("05EB8..."),
                Cell::from("12.3"),
                Cell::from("..."),
            ]),
            Row::new(vec![
                Cell::from("14C03..."),
                Cell::from("19.8"),
                Cell::from("..."),
            ]),
            Row::new(vec![Cell::from("CF0A7..."), Cell::from("5.6"), Cell::from("...")]),
            Row::new(vec![
                Cell::from("23A26..."),
                Cell::from("30.1"),
                Cell::from("..."),
            ]),
        ];

        let widths = [
            Constraint::Length(10),
            Constraint::Length(15),
            Constraint::Length(10),
        ];

        let deposit_cell_table = Table::new(gen_cells(), &widths)
            .column_spacing(1)
            .header(
                Row::new(vec!["From", "Value", "Tokens"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .highlight_symbol(">");

        f.render_widget(
            deposit_cell_table.block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Title::from(" Unprocessed Deposits "))
                    .border_type(BorderType::Rounded)
                    .padding(Padding::uniform(1)),
            ),
            second_row[2],
        );

        let main_row = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rows[2]);

        f.render_widget(
            Paragraph::new(
                r#"STRATEGY
  - Sequential deposits
  - 'n' deposits at a time 
            "#,
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Title::from(" Make Deposits "))
                    .border_type(BorderType::Rounded)
                    .padding(Padding::uniform(1)),
            ),
            main_row[0],
        );

        f.render_widget(
            Paragraph::new(
                r#" SELECT RECIPIENTS
  1. 9hVmDmyrLoNAupFVoobZRCfbwDWnAvCmjT1KCS4yGy3XziaCyMF
  2. 9etVzf2G2FtYsnKT187ZYe8HFKkMmVqrNByAAk3ofhm58BswBc3
            "#,
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Title::from(" Make Withdrawals "))
                    .border_type(BorderType::Rounded)
                    .padding(Padding::uniform(1)),
            ),
            main_row[1],
        );

        Ok(())
    }
}

fn render_status_line(vault_manager_status: &Option<VaultStatus<ExtraErgoData>>) -> Line {
    let mut spans = vec![Span::styled(
        "Connector status: ",
        Style::default().add_modifier(Modifier::BOLD),
    )];

    match vault_manager_status {
        Some(VaultStatus::Synced {
            current_progress_point,
            pending_export_status,
        }) => {
            spans.push(Span::styled("Sync'ed", Style::default().fg(Color::Green)));
            spans.push(Span::styled(
                format!(", @ block height: {}", u64::from(current_progress_point.point)),
                Style::default(),
            ));
        }
        Some(VaultStatus::Syncing {
            current_progress_point,
            num_points_remaining,
            pending_export_status,
        }) => {
            let extra_spans = vec![
                Span::styled("Syncing", Style::default().fg(Color::Yellow)),
                Span::styled(
                    format!(", @ block height: {}", u64::from(current_progress_point.point)),
                    Style::default(),
                ),
                Span::styled(
                    format!(", # blocks remaining: {}", num_points_remaining),
                    Style::default(),
                ),
            ];
            spans.extend(extra_spans);
        }
        None => {
            spans.push(Span::styled("Unknown", Style::default()));
        }
    };
    Line::from(spans)
}

fn gen_tx_rows<'a>() -> Vec<Row<'a>> {
    let mut rng = OsRng;
    let n = rng.gen_range(10..30);
    let tx_type = ["DEPOSIT", "WITHDRAWAL"];
    let mut res = vec![];

    let mut height = 1158826;

    for _ in 0..30 {
        res.push(Row::new(vec![
            Cell::from(tx_type[rng.gen_range(0_usize..2)]),
            Cell::from(generate_random_hex()),
            Cell::from(format!("{:.4}", rng.gen_range(10.2..26.5))),
            Cell::from(rng.gen_range(1..11).to_string()),
            Cell::from(rng.gen_range(10..100000).to_string()),
            Cell::from(height.to_string()),
            Cell::from("CONFIRMED").style(Style::default().fg(Color::Green)),
        ]));

        height -= rng.gen_range(20..40);
    }
    res
}

fn gen_cells<'a>() -> Vec<Row<'a>> {
    let mut rng = OsRng;
    let n = rng.gen_range(10..30);
    let tx_type = ["DEPOSIT", "WITHDRAWAL"];
    let mut res = vec![];

    let mut height = 1158826;

    for _ in 0..30 {
        res.push(Row::new(vec![
            Cell::from(generate_random_hex()),
            Cell::from(format!("{:.4}", rng.gen_range(10.2..26.5))),
            Cell::from("..."),
        ]));

        height -= rng.gen_range(20..40);
    }
    res
}

fn generate_random_hex() -> String {
    let hex_chars: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .filter(|c| c.is_ascii_hexdigit())
        .take(5)
        .map(char::from)
        .collect();

    format!("{}...", hex_chars)
}

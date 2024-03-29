use color_eyre::eyre::Result;
use crossterm::event::KeyEvent;
use ergo_lib::ergotree_ir::chain::ergo_box::BoxId;
use log::error;
use ratatui::prelude::Rect;
use spectrum_chain_connector::{ConnectorResponse, InboundValue};
use spectrum_ergo_connector::rocksdb::vault_boxes::ErgoNotarizationBounds;
use spectrum_ergo_connector::script::ExtraErgoData;
use spectrum_ergo_connector::AncillaryVaultInfo;
use spectrum_move::SerializedValue;
use tokio::sync::{mpsc, oneshot};

use crate::components::{home::Home, Component};
use crate::FrontEndCommand;
use crate::{action::Action, config::Config, event, mode::Mode, tui};

pub struct App {
    pub config: Config,
    pub tick_rate: f64,
    pub frame_rate: f64,
    pub components: Vec<Box<dyn Component>>,
    pub should_quit: bool,
    pub should_suspend: bool,
    pub mode: Mode,
    pub last_tick_key_events: Vec<KeyEvent>,
}

impl App {
    pub fn new(
        tick_rate: f64,
        frame_rate: f64,
        allowed_withdrawal_destinations: Vec<SerializedValue>,
    ) -> Result<Self> {
        let home = Home::new(allowed_withdrawal_destinations);
        let config = Config::new("".into(), "".into())?;
        let mode = Mode::Home;
        Ok(Self {
            tick_rate,
            frame_rate,
            components: vec![Box::new(home)],
            should_quit: false,
            should_suspend: false,
            config,
            mode,
            last_tick_key_events: Vec::new(),
        })
    }

    pub async fn run(
        &mut self,
        mut rx: tokio::sync::mpsc::Receiver<
            ConnectorResponse<ExtraErgoData, ErgoNotarizationBounds, BoxId, AncillaryVaultInfo>,
        >,
        command_tx: tokio::sync::mpsc::Sender<FrontEndCommand>,
    ) -> Result<()> {
        let (action_tx, mut action_rx) = mpsc::unbounded_channel();

        let mut tui = tui::Tui::new()?
            .tick_rate(self.tick_rate)
            .frame_rate(self.frame_rate);
        // tui.mouse(true);
        tui.enter()?;

        for component in self.components.iter_mut() {
            component.register_action_handler(action_tx.clone())?;
        }

        for component in self.components.iter_mut() {
            component.register_config_handler(self.config.clone())?;
        }

        for component in self.components.iter_mut() {
            component.init(tui.size()?)?;
        }

        loop {
            if let Some(e) = tui.next().await {
                match e {
                    tui::Event::Quit => action_tx.send(Action::Quit)?,
                    tui::Event::Tick => action_tx.send(Action::Tick)?,
                    tui::Event::Render => action_tx.send(Action::Render)?,
                    tui::Event::Resize(x, y) => action_tx.send(Action::Resize(x, y))?,
                    tui::Event::Key(key) => {
                        if let Some(keymap) = self.config.keybindings.get(&self.mode) {
                            if let Some(action) = keymap.get(&vec![key]) {
                                log::info!("Got action: {action:?}");
                                action_tx.send(action.clone())?;
                            } else {
                                // If the key was not handled as a single key action,
                                // then consider it for multi-key combinations.
                                self.last_tick_key_events.push(key);

                                // Check for multi-key combinations
                                if let Some(action) = keymap.get(&self.last_tick_key_events) {
                                    log::info!("Got action: {action:?}");
                                    action_tx.send(action.clone())?;
                                }
                            }
                        };
                    }
                    _ => {}
                }
                for component in self.components.iter_mut() {
                    if let Some(action) = component.handle_events(Some(event::Event::Tui(e.clone())))? {
                        action_tx.send(action)?;
                    }
                }
            }

            if let Ok(response) = rx.try_recv() {
                for component in self.components.iter_mut() {
                    if let Some(action) =
                        component.handle_events(Some(event::Event::Connector(response.clone())))?
                    {
                        action_tx.send(action)?;
                    }
                }
            }

            while let Ok(action) = action_rx.try_recv() {
                if action != Action::Tick && action != Action::Render {
                    log::debug!("{action:?}");
                }
                match &action {
                    Action::Tick => {
                        self.last_tick_key_events.drain(..);
                    }
                    Action::Quit => self.should_quit = true,
                    Action::Suspend => self.should_suspend = true,
                    Action::Resume => self.should_suspend = false,
                    Action::Resize(w, h) => {
                        tui.resize(Rect::new(0, 0, *w, *h))?;
                        tui.draw(|f| {
                            for component in self.components.iter_mut() {
                                let r = component.draw(f, f.size());
                                if let Err(e) = r {
                                    action_tx
                                        .send(Action::Error(format!("Failed to draw: {:?}", e)))
                                        .unwrap();
                                }
                            }
                        })?;
                    }
                    Action::Render => {
                        tui.draw(|f| {
                            for component in self.components.iter_mut() {
                                let r = component.draw(f, f.size());
                                if let Err(e) = r {
                                    action_tx
                                        .send(Action::Error(format!("Failed to draw: {:?}", e)))
                                        .unwrap();
                                }
                            }
                        })?;
                    }
                    Action::RequestDepositProcessing => {
                        command_tx
                            .send(FrontEndCommand::RequestDepositProcessing)
                            .await
                            .unwrap();
                    }
                    Action::RequestWithdrawal(term_cells) => {
                        command_tx
                            .send(FrontEndCommand::RequestWithdrawal(term_cells.clone()))
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
                for component in self.components.iter_mut() {
                    if let Some(action) = component.update(action.clone())? {
                        if let Err(e) = action_tx.send(action) {
                            error!(target: "driver", "Error sending Action {:?}", e);
                        }
                    };
                }
            }
            if self.should_suspend {
                tui.suspend()?;
                action_tx.send(Action::Resume)?;
                tui = tui::Tui::new()?
                    .tick_rate(self.tick_rate)
                    .frame_rate(self.frame_rate);
                // tui.mouse(true);
                tui.enter()?;
            } else if self.should_quit {
                let (notify, confirm) = oneshot::channel();
                command_tx.send(FrontEndCommand::Quit(notify)).await.unwrap();
                confirm.await.unwrap();
                tui.stop()?;
                break;
            }
        }
        tui.exit()?;
        Ok(())
    }
}

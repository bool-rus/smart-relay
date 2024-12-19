use serde::{Deserialize, Serialize};

use crate::{blinker::BlinkerMessage, ledboard::{self, LedBoard}};


#[derive(Serialize, Deserialize, Clone)]
pub struct WifiCreds {
    pub ssid: String,
    pub pass: String,
}
pub enum Message {
    ActivateRelay(u8),
    ConnectWifi(WifiCreds),
    ShowText(String),
    LedOn,
    LedOff,
    Blinker(BlinkerMessage),
    LedBoard(ledboard::Message),
}

impl From<BlinkerMessage> for Message {
    fn from(value: BlinkerMessage) -> Self {
        Self::Blinker(value)
    }
}
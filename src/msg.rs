use serde::{Deserialize, Serialize};

use crate::{blinker,ledboard};

pub enum Message {
    ActivateRelay(u8),
    SetWifi(crate::config::Wifi),
    ConnectWifi,
    Blinker(blinker::Message),
    LedBoard(ledboard::Message),
}

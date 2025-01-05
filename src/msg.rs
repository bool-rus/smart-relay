use serde::{Deserialize, Serialize};

use crate::{blinker,ledboard};

pub enum Message {
    ActivateRelay(u8),
    ConnectWifi(crate::config::Wifi),
    Blinker(blinker::Message),
    LedBoard(ledboard::Message),
}

use crate::ledboard::Color;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct Led {
    pub color: Option<Color>,
    pub width: Option<usize>,
    pub move_period: Option<u64>,
    pub text: Option<String>,
    pub lt_delta: Option<u64>,
    pub move_step: Option<usize>,
    pub font: Option<Vec<Symbol>>,
    pub space_width: Option<u8>,
}

#[derive(Deserialize)]
pub struct Symbol {
    pub symbol: char,
    pub mask: [u8;8],
}


#[derive(Serialize, Deserialize, Clone)]
pub struct Wifi {
    pub ssid: String,
    pub pass: String,
}
#[derive(Deserialize)]
pub struct Config {
    pub wifi: Option<Wifi>,
    pub led: Option<Led>,
}
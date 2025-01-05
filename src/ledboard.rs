use std::{collections::HashMap, iter, sync::Arc, time::Duration};
use crossbeam::channel::*;
use esp_idf_svc::{hal::{delay::FreeRtos, gpio::{AnyOutputPin, OutputPin}, peripheral::Peripheral, rmt::{PinState, Pulse, RmtChannel, Signal, Symbol, TxRmtConfig, TxRmtDriver}, units::Hertz}, nvs::{EspDefaultNvs, EspDefaultNvsPartition, NvsDefault}, timer::{EspTimer, EspTimerService, Task}};
use serde::{Deserialize, Serialize};
use ws2812_esp32_rmt_driver::*;
use anyhow::Result;

use crate::{font::Font, OkOrLog};
const BOARD_HEIGHT: usize = u8::BITS as usize;

pub enum Message {
    Text(String),
    Move,
    SetChar(char, Vec<u8>),
    SetMovePeriod(Duration),
    SetBoardWith(usize),
    SetColor(Color),
}


#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
pub struct Color {pub r: u8, pub g: u8, pub b: u8}
impl Color {
    pub fn make_pixel(&self, mask: u8) -> [u8;3] {
        [self.g*mask, self.r*mask, self.b*mask]
    }
}

struct Storage(EspDefaultNvs);

impl Storage {
    const WIDTH: &'static str = "WIDTH";
    const TEXT: &'static str = "TEXT";
    const PERIOD: &'static str = "PERIOD";
    const COLOR: &'static str = "COLOR";
    fn new(partition: EspDefaultNvsPartition) -> Result<Self> {
        let nvs = EspDefaultNvs::new(partition, "lb", true)?;
        Ok(Self(nvs))
    }
    fn board_width(&self) -> usize {
        self.0.get_u32(Self::WIDTH).ok_or_log().flatten().unwrap_or(32) as usize
    }
    fn set_board_width(&self, width: usize) {
        self.0.set_u32(Self::WIDTH, width as u32).ok_or_log();
    }
    fn text(&self) -> String {
        let mut buf = vec![0u8;crate::MAX_BUFFER_SIZE];
        self.0.get_raw(Self::TEXT, &mut buf).ok()
            .flatten().map(|bytes|Vec::from(bytes))
            .map(|v|String::from_utf8(v).ok())
            .flatten().unwrap_or("Привет!".to_string())
    }
    fn set_text(&mut self, text: &str) {
        let bytes = text.as_bytes();
        if bytes.len() > crate::MAX_BUFFER_SIZE {
            log::error!("Text limit exceeded: {}", bytes.len());
            return;
        }
        self.0.set_raw(Self::TEXT, bytes).ok_or_log();
    }
    fn move_period(&self) -> Duration {
        let ms = self.0.get_u64(Self::PERIOD).ok_or_log().flatten().unwrap_or(60);
        Duration::from_millis(ms)
    }
    fn set_move_period(&self, period: Duration)  {
        self.0.set_u64(Self::PERIOD, period.as_millis() as u64).ok_or_log();
    }
    fn color(&self) -> Color {
        self.0.get_u32(Self::COLOR).ok_or_log().flatten().map(|n|{
            let [r,g,b, _] = n.to_ne_bytes();
            Color {r,g,b}
        }).unwrap_or(Color {r: 64, g:0, b: 0})
    }
    fn set_color(&self, color: Color) {
        let Color {r,g,b} = color;
        self.0.set_u32(Self::COLOR, u32::from_ne_bytes([r,g,b,0])).ok_or_log();
    }
}

pub struct LedBoard {
    board_width: usize,
    cache: Vec<u8>,
    offset: usize,
    driver: Ws2812Esp32RmtDriver<'static>,
    timer: EspTimer<'static>,
    tx: Sender<Message>,
    rx: Receiver<Message>,
    color: Color,
    font: Font,
    storage: Storage,
}

impl LedBoard {
    pub fn new(
        partition: EspDefaultNvsPartition,
        timer: &EspTimerService<Task>,
        channel: impl Peripheral<P = impl RmtChannel> + 'static, 
        pin: impl Peripheral<P = impl OutputPin> + 'static
    ) -> Result<Self> {
        let (tx,rx) = crossbeam::channel::unbounded();
        let storage = Storage::new(partition)?;
        let txc = tx.clone();
        let timer = timer.timer(move ||{txc.send(Message::Move).ok_or_log();})?;
        let font = Font::new();
        let text = storage.text();
        let cache = font.render(&text);
        let board_width = storage.board_width();
        let color = storage.color();
        let move_period = storage.move_period();
        log::info!("Starting ledboard with config: \n\ttext: {text}\n\tboard with: {board_width}\n\tcolor: {color:?}\n\tmove period: {} ms", move_period.as_millis());
        timer.every(move_period)?;
        Ok(Self{tx, rx, timer,
            driver: Ws2812Esp32RmtDriver::new(channel, pin)?, 
            color, 
            font, 
            board_width, 
            offset: 0,
            cache,
            storage,
        })
    }
    pub fn tx(&self) -> Sender<Message> {
        self.tx.clone()
    }

    pub fn process(&mut self) -> Result<()> {
        loop {
            match self.rx.try_recv() {
                Ok(msg) => match self.process_iteration(msg) {
                    Ok(_) => {},
                    Err(e) => log::error!("ledboard: {e:?}"),
                },
                Err(TryRecvError::Empty) => break Ok(()),
                Err(e) => Err(e)?,
            }
        }
    }
    fn process_iteration(&mut self, msg: Message) -> Result<()> {
        match msg {
            Message::Text(text) => {
                self.cache = self.font.render(&text);
                self.offset = 0;
                self.storage.set_text(&text);
                log::info!("received text: {text}");
            },
            Message::Move => {
                self.offset +=1;
                if self.offset > self.cache.len() + self.board_width {
                    self.offset = 0;
                }
                self.draw()?;
            },
            Message::SetChar(c, mask) => self.font.set_char(c, mask),
            Message::SetMovePeriod(period) => {
                self.timer.every(period)?;
                self.storage.set_move_period(period);
                log::info!("received move period option: {} ms", period.as_millis());
            },
            Message::SetBoardWith(width) => {
                self.board_width = width;
                self.storage.set_board_width(width);
                log::info!("received board width: {width}");
            },
            Message::SetColor(color) => {
                self.color = color;
                self.storage.set_color(color);
                log::info!("received color: {color:?}");
            }
        }
        Ok(())
    }
    pub fn draw(&mut self) -> Result<()> {
        let columns = self.board_width;
        let pixels:Vec<_> = iter::repeat(0).take(columns)
            .chain(self.cache.iter().copied())
            .chain(iter::repeat(0))
            .skip(self.offset).take(columns)
            .enumerate().map(|(n, m)|if n%2 == 1 {m.reverse_bits()} else {m})//это потому что диоды соединены зиг-загом
            .collect();
        let color = self.color;
        let seq = pixels.into_iter().flat_map(|m|{
            (0..u8::BITS).map(move |n|(m >> n) & 1)
        }).flat_map(move |dot|color.make_pixel(dot).into_iter());
        self.driver.write(seq)?;
        Ok(())
    }
    pub fn move_period(&self, period: Duration) -> Result<()> {
        self.timer.every(period)?;
        Ok(())
    }
}



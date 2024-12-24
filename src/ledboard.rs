use std::{collections::HashMap, iter, sync::Arc, time::Duration};

use crossbeam::channel::*;
use esp_idf_svc::{hal::{delay::FreeRtos, gpio::{AnyOutputPin, OutputPin}, peripheral::Peripheral, rmt::{PinState, Pulse, RmtChannel, Signal, Symbol, TxRmtConfig, TxRmtDriver}, units::Hertz}, timer::{EspTimer, EspTimerService, Task}};
use ws2812_esp32_rmt_driver::*;
use anyhow::Result;

use crate::font::Font;
const BOARD_HEIGHT: usize = u8::BITS as usize;

pub enum Message {
    Text(String),
    Move,
    SetChar(char, Vec<u8>),
    SetMovePeriod(Duration),
    SetLedsCount(usize),
    SetColor(Color),
}

#[derive(Clone, Copy)]
pub struct Color {pub r: u8, pub g: u8, pub b: u8}
impl Color {
    pub fn make_pixel(&self, mask: u8) -> [u8;3] {
        [self.g*mask, self.r*mask, self.b*mask]
    }
}

pub struct LedBoard {
    leds_count: usize,
    cache: Vec<u8>,
    offset: usize,
    driver: Ws2812Esp32RmtDriver<'static>,
    timer: EspTimer<'static>,
    tx: Sender<Message>,
    rx: Receiver<Message>,
    color: Color,
    font: Font,
}

impl LedBoard {
    pub fn new(
        timer: &EspTimerService<Task>,
        channel: impl Peripheral<P = impl RmtChannel> + 'static, 
        pin: impl Peripheral<P = impl OutputPin> + 'static
    ) -> Result<Self> {
        let (tx,rx) = crossbeam::channel::unbounded();
        let txc = tx.clone();
        let timer = timer.timer(move ||{txc.send(Message::Move);})?;
        timer.every(Duration::from_millis(60))?;
        tx.send(Message::Text("*** С наступающим 2025 годом! Всем здоровья, достатка, благополучия, добра и мира в новом году! ***".to_owned()));
        Ok(Self{tx, rx, timer,
            driver: Ws2812Esp32RmtDriver::new(channel, pin)?, 
            color: Color {r: 64, g:0, b:0}, 
            font: Font::new(), 
            leds_count: 512, 
            offset: 0,
            cache: vec![0],
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
                log::info!("received text: {text}");
            },
            Message::Move => {
                log::info!("process move, offset: {}", self.offset);
                self.offset +=1;
                if self.offset > self.cache.len() + 2 * self.leds_count / BOARD_HEIGHT {
                    self.offset = 0;
                }
                self.draw()?;
            },
            Message::SetChar(c, mask) => self.font.set_char(c, mask),
            Message::SetMovePeriod(duration) => self.timer.every(duration)?,
            Message::SetLedsCount(count) => self.leds_count = count,
            Message::SetColor(color) => self.color = color,
        }
        Ok(())
    }
    pub fn draw(&mut self) -> Result<()> {
        let columns = self.leds_count / BOARD_HEIGHT;
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



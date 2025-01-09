use std::{collections::HashMap, iter, time::{Duration, Instant}};
use crossbeam::channel::*;
use esp_idf_svc::timer::{EspTimer, EspTimerService, Task};
use esp_idf_svc::nvs::{EspDefaultNvs, EspDefaultNvsPartition};
use esp_idf_svc::hal::{peripheral::Peripheral, rmt::RmtChannel};
use esp_idf_svc::hal::gpio::OutputPin;
use serde::{Deserialize, Serialize};
use crate::driver::Driver;
use crate::config::Symbol;
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
    LowTimingDelta(u64),
    SetMoveStep(usize),
    SetFont(Vec<Symbol>),
    SetSpaceWidth(u8),
}

fn render(text: &str, storage: &Storage, defaults: &HashMap<char, u64>) -> Vec<u8> { //bit-mask
    let space_width = storage.space_width();
    text.chars().map(|c| {
        let m = storage.symbol(c);
        if m == 0 {
            defaults.get(&c).copied().unwrap_or(0)
        } else {m}
    }).flat_map(|m|{
        let bytes = m.to_ne_bytes();
        //ищем первый ненулевой байт
        let mut skip = u8::BITS - space_width as u32 % u8::BITS;
        let mut i = 0;
        for b in bytes {
            if b > 0 {
                skip = i;
                break;
            }
            i+=1;
        }
        bytes.into_iter().skip(skip as usize).chain(std::iter::once(0))
    }).collect()
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
    const LTDELTA: &'static str = "LTDELTA";
    const MOVE_STEP: &'static str = "MSTEP";
    const SPACE_WIDTH: &'static str = "SPACE";
    fn make_liter(c: char) -> String {
        format!("L{c}")
    }
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
    fn lt_delta(&self) -> u64 {
        self.0.get_u64(Self::LTDELTA).ok_or_log().flatten().unwrap_or_default()
    }
    fn set_lt_delta(&self, delta: u64) {
        self.0.set_u64(Self::LTDELTA, delta).ok_or_log();
    } 
    fn move_step(&self) -> usize {
        self.0.get_u32(Self::MOVE_STEP).ok_or_log().flatten().unwrap_or(1) as usize
    }
    fn set_move_step(&self, step: usize) {
        self.0.set_u32(Self::MOVE_STEP, step as u32).ok_or_log();
    }
    fn symbol(&self, c: char) -> u64 {
        self.0.get_u64(Self::make_liter(c).as_str()).ok_or_log().flatten().unwrap_or_default()
    }
    fn set_symbol(&self, c: char, value: u64) {
        self.0.set_u64(Self::make_liter(c).as_str(), value).ok_or_log();
    }
    fn space_width(&self) -> u8 {
        self.0.get_u8(Self::SPACE_WIDTH).ok_or_log().flatten().unwrap_or(4)
    }
    fn set_space_width(&self, width: u8) {
        self.0.set_u8(Self::SPACE_WIDTH, width as u8).ok_or_log();
    }
}

pub struct LedBoard {
    board_width: usize,
    move_step: usize,
    cache: Vec<u8>,
    offset: usize,
    driver: Driver<'static>,
    timer: EspTimer<'static>,
    tx: Sender<Message>,
    rx: Receiver<Message>,
    color: Color,
    font: Font,
    storage: Storage,
    drawing: Instant,
}

impl LedBoard {
    const BOARD_HEIGHT: usize = 8;
    const COLOR_BYTES: usize = 3;
    pub fn new(
        partition: EspDefaultNvsPartition,
        timer: &EspTimerService<Task>,
        channel: impl Peripheral<P = impl RmtChannel> + 'static, 
        pin: impl Peripheral<P = impl OutputPin> + 'static
    ) -> Result<Self> {
        let (tx,rx) = crossbeam::channel::bounded(10);
        let storage = Storage::new(partition)?;
        let txc = tx.clone();
        let timer = timer.timer(move ||{txc.send(Message::Move).ok_or_log();})?;
        let font = Font::new();
        let text = storage.text();
        let cache = render(&text, &storage, &font.symbols);
        let board_width = storage.board_width();
        let color = storage.color();
        let move_period = storage.move_period();
        let move_step = storage.move_step();
        let lt_delta = storage.lt_delta();
        log::info!("Starting ledboard with config: \n\ttext: {text}\n\tboard with: {board_width}\n\tcolor: {color:?}\n\tmove period: {} ms\n\tmove step: {move_step}\n\tlt_delta: {lt_delta} ns", move_period.as_millis());
        let mut driver = Driver::new(channel, pin)?;
        driver.set_lt_delta(lt_delta)?;
        timer.every(move_period)?;
        let drawing = Instant::now();
        Ok(Self{tx, rx, timer,
            driver, 
            color, 
            font, 
            board_width, 
            move_step,
            offset: 0,
            cache,
            storage,
            drawing,
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
    fn min_move_period(&self, delta: u64) -> Duration{
        Duration::from_millis(5) + Duration::from_nanos(
            u8::BITS as u64 * (self.board_width * Self::BOARD_HEIGHT * Self::COLOR_BYTES) as u64 * (crate::driver::Driver::BIT_TIMING + delta)
        )
    }
    fn process_iteration(&mut self, msg: Message) -> Result<()> {
        match msg {
            Message::Text(text) => {
                let d = Instant::now();
                self.cache = render(&text, &self.storage, &self.font.symbols);
                let d = d.elapsed();
                self.offset = 0;
                self.storage.set_text(&text);
                log::info!("received text: {text}, rendered at {} ms", d.as_millis());
            },
            Message::Move => {
                self.offset +=self.move_step;
                if self.offset > self.cache.len() + self.board_width {
                    self.offset = 0;
                }
                self.draw()?;
            },
            Message::SetChar(c, mask) => self.font.set_char(c, mask),
            Message::SetMovePeriod(period) => {
                log::info!("received move period option: {} ms", period.as_millis());
                let min_move_period = self.min_move_period(self.storage.lt_delta());
                let period =  if min_move_period > period {
                    log::info!("need to increase move period to {} ms", min_move_period.as_millis());
                    min_move_period
                } else {period};
                self.timer.every(period)?;
                self.storage.set_move_period(period);
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
            },
            Message::LowTimingDelta(delta) => {
                self.driver.set_lt_delta(delta)?;
                let min_move_period = self.min_move_period(delta);
                if min_move_period > self.storage.move_period() {
                    self.timer.every(min_move_period)?;
                    self.storage.set_move_period(min_move_period);
                    log::info!("need to increase move period to {} ms", min_move_period.as_millis());
                }
                self.storage.set_lt_delta(delta);
                log::info!("received lt_delta: {delta}");
            }
            Message::SetMoveStep(step) => {
                self.move_step = step;
                self.storage.set_move_step(step);
                log::info!("received move step: {step}");
            }
            Message::SetFont(symbols) => {
                let symbols: Vec<_> = symbols.into_iter().map(|Symbol { symbol, mask }|{
                    self.storage.set_symbol(symbol, u64::from_ne_bytes(mask));
                    symbol
                }).collect();
                log::info!("Received symbols: {symbols:?}");
            },
            Message::SetSpaceWidth(width) => {
                let width = width as u32 % u8::BITS;
                self.storage.set_space_width(width as u8);
                log::info!("received space width: {width}");
            },
        }
        Ok(())
    }
    pub fn draw(&mut self) -> Result<()> {
        let columns = self.board_width;
        let buf: Vec<_> = iter::repeat(&0).take(columns)
            .chain(self.cache.iter())
            .chain(iter::repeat(&0))
            .skip(self.offset).take(columns)
            .copied()
            .enumerate().map(|(n, m)|if n%2 == 1 {m.reverse_bits()} else {m})//это потому что диоды соединены зиг-загом
            .collect();

        let color = self.color;
        let seq = buf.into_iter().take(columns).flat_map(|m|{
            (0..u8::BITS).map(move |n|(m >> n) & 1)
        }).flat_map(move |dot|color.make_pixel(dot).into_iter());
        let instant = std::time::Instant::now();
        self.driver.write(seq)?;
        let elapsed = instant.elapsed();
        //log::info!("drawed frame at {} ms", elapsed.as_millis());
        Ok(())
    }
    pub fn move_period(&self, period: Duration) -> Result<()> {
        self.timer.every(period)?;
        Ok(())
    }
}



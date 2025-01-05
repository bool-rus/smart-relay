use std::time::Duration;

use crossbeam::channel::{Receiver, Sender, TryRecvError};
use esp_idf_svc::{hal::gpio::{AnyOutputPin, PinDriver}, timer::{EspTimer, EspTimerService}};
use anyhow::{bail, Result};


pub enum Message {
    Low,
    High,
}

pub struct Blinker {
    pin: PinDriver<'static, AnyOutputPin, esp_idf_svc::hal::gpio::Output>, 
    timer: EspTimer<'static>,
    tx: Sender<Message>,
    rx: Receiver<Message>,
}

impl Blinker {
    pub fn new(timer_service: &EspTimerService<esp_idf_svc::timer::Task>, pin: AnyOutputPin) -> Result<Self> {
        let pin = PinDriver::output(pin)?;
        let (tx, rx) = crossbeam::channel::unbounded();
        let txc = tx.clone();
        let timer = timer_service.timer(move||{txc.send(Message::Low.into());})?;
        Ok(Self {pin, timer, tx, rx})
    }
    pub fn tx(&self) -> Sender<Message> {
        self.tx.clone()
    }
    pub fn process(&mut self)  -> Result<()>{
        match self.rx.try_recv() {
            Ok(msg) => self.process_iteration(msg)?,
            Err(TryRecvError::Empty) => return Ok(()),
            Err(TryRecvError::Disconnected) => bail!("blinker channel closed"),
        }
        Ok(())
    }
    pub fn process_iteration(&mut self, msg: Message) -> Result<()> {
        match msg {
            Message::Low => {self.pin.set_low()?;},
            Message::High => {
                self.pin.set_high()?;
                self.timer.after(Duration::from_secs(1))?;
            },
        }
        Ok(())
    }
}
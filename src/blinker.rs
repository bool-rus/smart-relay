use std::time::Duration;

use crossbeam::channel::Sender;
use esp_idf_svc::{hal::gpio::{AnyOutputPin, PinDriver}, timer::{EspTimer, EspTimerService}};
use anyhow::Result;


pub enum BlinkerMessage {
    Low,
    High,
}

pub struct Blinker<T> {
    pin: PinDriver<'static, AnyOutputPin, esp_idf_svc::hal::gpio::Output>, 
    timer: EspTimer<'static>,
    tx: Sender<T>
}

impl<T: From<BlinkerMessage> + Send + Sync + 'static> Blinker<T> {
    pub fn new(pin: AnyOutputPin, timer_service: &EspTimerService<esp_idf_svc::timer::Task>, tx: Sender<T>) -> Result<Self> {
        let pin = PinDriver::output(pin)?;
        let txc = tx.clone();
        let timer = timer_service.timer(move||{txc.send(BlinkerMessage::Low.into());})?;
        Ok(Self {pin, timer, tx})
    }
    pub fn process(&mut self, msg: BlinkerMessage)  -> Result<()>{
        match msg {
            BlinkerMessage::Low => {self.pin.set_low()?;},
            BlinkerMessage::High => {
                self.pin.set_high()?;
                self.timer.after(Duration::from_secs(1))?;
            },
        }
        Ok(())
    }
}
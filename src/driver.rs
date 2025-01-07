use std::time::Duration;

use esp_idf_svc::hal::rmt::{PinState, Pulse};
use esp_idf_svc::sys::EspError;
use esp_idf_svc::hal::{gpio::OutputPin, peripheral::Peripheral};
use esp_idf_svc::hal::rmt::{config::TransmitConfig, RmtChannel, Symbol, TxRmtDriver};

const BIT0_TIMINGS: (u64, u64) = (400, 850);
const BIT1_TIMINGS: (u64, u64) = (800, 450);

pub struct Driver<'d> {
    drv: TxRmtDriver<'d>,
    bit0: Symbol,
    bit1: Symbol,
}

impl<'d> Driver<'d> {
    pub const BIT_TIMING: u64 = BIT0_TIMINGS.0 + BIT0_TIMINGS.1; 
    pub fn new<C: RmtChannel>(
        channel: impl Peripheral<P = C> + 'd,
        pin: impl Peripheral<P = impl OutputPin> + 'd,
    ) -> Result<Self, EspError> {
        let config = TransmitConfig::new().clock_divider(4).mem_block_num(2);
        let drv = TxRmtDriver::new(channel, pin, &config)?;

        let ticks_hz = drv.counter_clock()?;
        let (h,l) = BIT0_TIMINGS;
        let bit0 = Symbol::new(
            Pulse::new_with_duration(ticks_hz, PinState::High, &Duration::from_nanos(h))?, 
            Pulse::new_with_duration(ticks_hz, PinState::Low, &Duration::from_nanos(l))?,
        );
        let (h,l) = BIT1_TIMINGS;
        let bit1 = Symbol::new(
            Pulse::new_with_duration(ticks_hz, PinState::High, &Duration::from_nanos(h))?, 
            Pulse::new_with_duration(ticks_hz, PinState::Low, &Duration::from_nanos(l))?,
        );
        Ok(Self {drv, bit0, bit1})
    }
    pub fn write<I: Iterator<Item=u8> + Send + 'static>(&mut self, bytes: I) -> Result<(), EspError> {
        let bit0 = self.bit0;
        let bit1 = self.bit1;
        let one = 1u8.reverse_bits();
        let iter = bytes.into_iter().flat_map(move |b|{
            (0..u8::BITS).map(move |i| {
                if b<<i & one == 0 {
                    bit0
                } else {
                    bit1
                }
            })
        });
        self.drv.start_iter_blocking(iter)?;
        Ok(())
    }
    pub fn set_lt_delta(&mut self, delta: u64) -> Result<(), EspError> {
        let ticks_hz = self.drv.counter_clock()?;
        let (h,l) = BIT0_TIMINGS;
        self.bit0 = Symbol::new(
            Pulse::new_with_duration(ticks_hz, PinState::High, &Duration::from_nanos(h))?, 
            Pulse::new_with_duration(ticks_hz, PinState::Low, &Duration::from_nanos(l+delta))?,
        );
        let (h,l) = BIT1_TIMINGS;
        self.bit1 = Symbol::new(
            Pulse::new_with_duration(ticks_hz, PinState::High, &Duration::from_nanos(h))?, 
            Pulse::new_with_duration(ticks_hz, PinState::Low, &Duration::from_nanos(l+delta))?,
        );
        Ok(())
    }
}

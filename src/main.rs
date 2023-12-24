use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;

use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::delay::FreeRtos;
use esp_idf_svc::hal::gpio::{PinDriver, Output, AnyOutputPin};

use esp_idf_svc::hal::modem::Modem;
use esp_idf_svc::hal::prelude::Peripherals;
use esp_idf_svc::hal::reset::restart;
use anyhow::{Result, bail};
use esp_idf_svc::wifi::{BlockingWifi, EspWifi};

const INDEX_PAGE: &'static [u8] = include_bytes!("index.html");

const STACK_SIZE: usize = 10240;


fn main() {
    if let Some(_) = create_and_run("4G-UFI-24D", "1234567890").err() {
        restart();
    }
}


fn create_and_run(ssid: &str, passwd: &str) -> Result<()> {
    esp_idf_svc::sys::link_patches();
    let mut dev = MyDevice::create(ssid, passwd)?;
    dev.run()?;
    Ok(())
}


fn create_wifi(modem: Modem, ssid: &str, passwd: &str) -> anyhow::Result<BlockingWifi<EspWifi<'static>>> {
    use esp_idf_svc::wifi;

    use esp_idf_svc::nvs::EspDefaultNvsPartition;
    let sys_loop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;

    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(modem, sys_loop.clone(), Some(nvs))?,
        sys_loop,
    )?;

    let wifi_configuration = wifi::Configuration::Client(wifi::ClientConfiguration {
        ssid: ssid.into(),
        bssid: None,
        auth_method: wifi::AuthMethod::WPA2Personal,
        password: passwd.into(),
        channel: None,
    });
    wifi.set_configuration(&wifi_configuration)?;
    Ok(wifi)
}

fn start_server(flag: Arc<AtomicBool>) -> anyhow::Result<()> {
    use esp_idf_svc::http::server::*;
    use esp_idf_svc::io::*;
    let server_configuration = esp_idf_svc::http::server::Configuration {
        stack_size: STACK_SIZE,
        ..Default::default()
    };
    let mut server = EspHttpServer::new(&server_configuration)?;

    server.fn_handler("/", Method::Get, |req| {
        let mut resp = req.into_ok_response()?;
        resp.write_all(INDEX_PAGE)?;
        Ok(())
    })?;

    server.fn_handler("/activate/relay1", Method::Post, |req| {
        flag.store(true, Relaxed);
        let mut resp = req.into_ok_response()?;
        resp.write_all("Relay 1 activated".as_bytes())?;

        Ok(())
    })?;
    core::mem::forget(server);
    Ok(())
}

struct MyDevice {
    led: PinDriver<'static, AnyOutputPin, Output>,
    relay1: PinDriver<'static, AnyOutputPin, Output>,
    relay2: PinDriver<'static, AnyOutputPin, Output>,
    wifi: BlockingWifi<EspWifi<'static>>,
}

impl MyDevice {
    fn create(ssid: &str, passwd: &str) -> Result<Self> { 
        let peripherals = Peripherals::take()?;
        let wifi = create_wifi(peripherals.modem, ssid, passwd)?;

        let led_pin: AnyOutputPin = peripherals.pins.gpio15.into();
        let led = PinDriver::output(led_pin)?;

        let relay1: AnyOutputPin = peripherals.pins.gpio14.into();
        let relay2: AnyOutputPin = peripherals.pins.gpio13.into();
        let mut  relay = PinDriver::output(relay1)?;
        relay.set_high()?;
        let mut relay2 = PinDriver::output(relay2)?;
        relay2.set_high()?;
        
        Ok(Self {led, relay1: relay, relay2, wifi})
    }
    fn connect_wifi(&mut self) -> Result<()> {
        let on = 50;
        self.wifi.start()?;
        self.blink(1, on)?;
        self.wifi.connect()?;
        self.blink(2, on)?;
        self.wifi.wait_netif_up()?;
        self.blink(3, on)?;
        Ok(())
    }
    fn run(&mut self) -> Result<()> {
        self.blink(1, 1000)?;
        self.connect_wifi()?;
        let flag = Arc::new(AtomicBool::new(false));
        start_server(flag.clone())?;
        loop {
            FreeRtos::delay_ms(500);
            self.led.set_high()?;
            if flag.load(Relaxed) {
                self.enable_relay()?;
                flag.store(false, Relaxed);
            }
            if !self.wifi.is_connected()? {
                self.blink(30, 15)?;
                bail!("WiFi disconnected");
            }
            FreeRtos::delay_ms(50);
            self.led.set_low()?;
        }
    }
    fn blink(&mut self, n: u32, on: u32) -> Result<()> {
        for _ in 0..n {
            self.led.set_high()?;
            FreeRtos::delay_ms(on);
            self.led.set_low()?;
            FreeRtos::delay_ms(on);
        }
        Ok(())
    }
    fn enable_relay(&mut self) -> Result<()> {
        self.relay1.set_low()?;
        FreeRtos::delay_ms(1000);
        self.relay1.set_high()?;
        Ok(())
    }

}


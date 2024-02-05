
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;

use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::delay::FreeRtos;
use esp_idf_svc::hal::gpio::{PinDriver, Output, AnyOutputPin};

use esp_idf_svc::hal::modem::Modem;
use esp_idf_svc::hal::prelude::Peripherals;
use esp_idf_svc::hal::reset::restart;
use anyhow::{Result, bail};
use esp_idf_svc::log::EspLogger;
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};
use esp_idf_svc::wifi::{BlockingWifi, EspWifi};
use log::info;
use serde::{Deserialize, Serialize};

const INDEX_PAGE: &'static [u8] = include_bytes!("index.html");

const STACK_SIZE: usize = 10240;
const NS: &str = "wifi-auth-data";
const WIFI_CREDS: &str = "wifi-creds";

#[derive(Serialize, Deserialize, Clone)]
struct WifiCreds {
    ssid: String,
    pass: String,
}

#[derive(Default)]
struct Flags {
    relay1: AtomicBool,
    relay2: AtomicBool,
    creds: Mutex<Option<WifiCreds>>,
}

fn main() {
    EspLogger::initialize_default();
    if let Some(e) = create_and_run().err() {
        log::error!("received error: {:?}", e);
        info!("restarting...");
        restart();
    }
}


fn create_and_run() -> Result<()> {
    esp_idf_svc::sys::link_patches();
    let mut dev = SmartRelay::create()?;
    dev.run()?;
    Ok(())
}

fn create_ap_wifi(modem: Modem) -> anyhow::Result<BlockingWifi<EspWifi<'static>>> {
    let ssid = "smart-relay-ap";
    let pass = "booliscool";
    info!("Starting WiFi AP...");
    use esp_idf_svc::wifi;
    let sys_loop = EspSystemEventLoop::take()?;

    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(modem, sys_loop.clone(), None)?,
        sys_loop,
    )?;

    let wifi_configuration = wifi::Configuration::AccessPoint(wifi::AccessPointConfiguration {
        ssid: ssid.try_into().unwrap(),
        ssid_hidden: false,
        auth_method: wifi::AuthMethod::WPA2Personal,
        password: pass.try_into().unwrap(),
        channel: 11,
        ..Default::default()
    });
    wifi.set_configuration(&wifi_configuration)?;
    wifi.start()?;
    info!("WiFi AP started");
    Ok(wifi)
}

fn create_client_wifi(modem: Modem, ssid: &str, pass: &str) -> anyhow::Result<BlockingWifi<EspWifi<'static>>> {
    use esp_idf_svc::wifi;
    info!("Connecting to wifi as client");
    let sys_loop = EspSystemEventLoop::take()?;
    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(modem, sys_loop.clone(), None)?,
        sys_loop,
    )?;
    let wifi_configuration = wifi::Configuration::Client(wifi::ClientConfiguration {
        ssid: ssid.into(),
        bssid: None,
        auth_method: wifi::AuthMethod::WPA2Personal,
        password: pass.into(),
        channel: None,
    });
    wifi.set_configuration(&wifi_configuration)?;
    wifi.start()?;
    wifi.connect()?;
    info!("Wifi connected");
    Ok(wifi)
}

fn start_server(flags: Arc<Flags>) -> anyhow::Result<()> {
    info!("Starting server...");
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
        flags.relay1.store(true, Relaxed);
        let mut resp = req.into_ok_response()?;
        resp.write_all("Relay 1 activated".as_bytes())?;

        Ok(())
    })?;
    server.fn_handler("/activate/relay2", Method::Post, |req| {
        flags.relay2.store(true, Relaxed);
        let mut resp = req.into_ok_response()?;
        resp.write_all("Relay 2 activated".as_bytes())?;

        Ok(())
    })?;
    server.fn_handler("/update", Method::Post, |mut req| {
        let len = req.header("Content-Length").unwrap_or("0");
        let len: usize = len.parse().unwrap_or(0); 
        if len > 100 {
            req.into_status_response(413)?.write_all(b"Request too big")?;
            return Ok(());
        }
        let mut buf = vec![0u8; len];
        req.read_exact(&mut buf)?;
        let data = serde_json::from_slice::<WifiCreds>(&buf)?;
        {
            let mut creds = flags.creds.lock().unwrap();
            *creds = Some(data);
        }
        req.into_ok_response()?.write_all(b"OK")?;
        Ok(())
    })?;
    info!("Server started");
    core::mem::forget(server);
    Ok(())
}

struct SmartRelay {
    led: PinDriver<'static, AnyOutputPin, Output>,
    relay1: PinDriver<'static, AnyOutputPin, Output>,
    relay2: PinDriver<'static, AnyOutputPin, Output>,
    wifi: BlockingWifi<EspWifi<'static>>,
    nvs: EspNvs<NvsDefault>,
}

impl SmartRelay {
    fn create() -> Result<Self> { 
        let partition = EspDefaultNvsPartition::take()?;
        let mut nvs = EspNvs::new(partition.clone(), NS, true)?;
        info!("Got namespace from default partition");
        let mut buf = vec![0u8;100];
        let wifi_creds = nvs.get_raw(WIFI_CREDS, &mut buf)?
        .map(|data|serde_json::from_slice::<WifiCreds>(data));

        let peripherals = Peripherals::take()?;
        let wifi = match wifi_creds {
            Some(Ok(creds)) => create_client_wifi(peripherals.modem, &creds.ssid, &creds.pass),
            Some(Err(e)) => {
                log::error!("Cannot parse wifi credentials: {:?}", e);
                nvs.remove(WIFI_CREDS)?;
                create_ap_wifi(peripherals.modem)
            },
            None => create_ap_wifi(peripherals.modem)
        }?;

        let led_pin: AnyOutputPin = peripherals.pins.gpio15.into();
        let led = PinDriver::output(led_pin)?;

        let relay1: AnyOutputPin = peripherals.pins.gpio14.into();
        let relay2: AnyOutputPin = peripherals.pins.gpio13.into();
        let mut  relay1 = PinDriver::output(relay1)?;
        relay1.set_high()?;
        let mut relay2 = PinDriver::output(relay2)?;
        relay2.set_high()?;
        
        Ok(Self {led, relay1, relay2, wifi, nvs})
    }
    fn invoke_creds(flags: Arc<Flags>) -> Option<WifiCreds> {
        let mut creds = flags.creds.lock().unwrap();
        match creds.clone() {
            Some(c) => {
                *creds = None;
                Some(c)
            },
            None => None
        }
    }
    fn run(&mut self) -> Result<()> {
        self.wifi.wait_netif_up()?;
        let flags = Arc::new(Flags::default());
        start_server(flags.clone())?;
        loop {
            FreeRtos::delay_ms(500);
            self.led.set_high()?;
            if flags.relay1.load(Relaxed) {
                info!("activate relay 1");
                enable_on_sec(&mut self.relay1)?;
                flags.relay1.store(false, Relaxed);
            }
            if flags.relay2.load(Relaxed) {
                info!("activate relay 2");
                enable_on_sec(&mut self.relay2)?;
                flags.relay2.store(false, Relaxed);
            }
            if !self.wifi.is_connected()? {
                self.blink(30, 15)?;
                bail!("WiFi disconnected");
            }
            if let Some(c) = Self::invoke_creds(flags.clone()) {
                info!("received new wifi creds, esp will update and restart");
                let buf = serde_json::to_vec(&c)?;
                self.nvs.set_raw(WIFI_CREDS, &buf)?;
                restart();
            }
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

}

fn enable_on_sec(pin: &mut PinDriver<'static, AnyOutputPin, Output>) -> Result<()> {
    pin.set_low()?;
    FreeRtos::delay_ms(1000);
    pin.set_high()?;
    Ok(())
}
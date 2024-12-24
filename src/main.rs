
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, SystemTime};

use blinker::Blinker;
use crossbeam::channel::{Receiver, Sender, TryRecvError};
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::delay::FreeRtos;
use esp_idf_svc::hal::gpio::{PinDriver, Output, AnyOutputPin};

use esp_idf_svc::hal::modem::Modem;
use esp_idf_svc::hal::prelude::Peripherals;
use esp_idf_svc::hal::reset::restart;
use anyhow::{Result, bail};
use esp_idf_svc::http::server::EspHttpServer;
use esp_idf_svc::log::EspLogger;
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};
use esp_idf_svc::timer::{EspTimerService, Task};
use esp_idf_svc::wifi::{BlockingWifi, EspWifi};
use ledboard::LedBoard;
use log::info;
use msg::{Message, WifiCreds};
use serde::{Deserialize, Serialize};

const SLEEP_MS: u32 = 1;
const INDEX_PAGE: &'static [u8] = include_bytes!("index.html");

const STACK_SIZE: usize = 10240;
const NS: &str = "wifi-auth-data";
const WIFI_CREDS: &str = "wifi-creds";

mod ledboard;
mod msg;
mod font;
mod blinker;

#[derive(Default)]
struct Flags {
    relay1: AtomicBool,
    relay2: AtomicBool,
    creds: Mutex<Option<WifiCreds>>,
}

fn main() {
    esp_idf_svc::sys::link_patches();
    EspLogger::initialize_default();
    for i in 0..3 {
        let t = std::time::SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
        info!("привет {i}: {}", t.as_secs());
        FreeRtos::delay_ms(1000);
    }

    if let Some(e) = create_and_run().err() {
        log::error!("received error: {:?}", e);
        info!("restarting...");
        restart();
    }
}


fn create_and_run() -> Result<()> {
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
        ssid: ssid.try_into().unwrap(),
        bssid: None,
        auth_method: wifi::AuthMethod::WPA2Personal,
        password: pass.try_into().unwrap(),
        channel: None,
        pmf_cfg: Default::default(),
        scan_method: wifi::ScanMethod::FastScan,
    });
    wifi.set_configuration(&wifi_configuration)?;
    wifi.start()?;
    wifi.connect()?;
    info!("Wifi connected");
    Ok(wifi)
}

fn start_server(tx: Sender<Message>) -> anyhow::Result<EspHttpServer<'static>> {
    info!("Starting server...");
    use esp_idf_svc::http::server::*;
    use esp_idf_svc::io::*;
    let server_configuration = esp_idf_svc::http::server::Configuration {
        stack_size: STACK_SIZE,
        ..Default::default()
    };
    let mut server = EspHttpServer::new(&server_configuration)?;

    server.fn_handler::<EspIOError, _>("/", Method::Get, |req| {
        let mut resp = req.into_ok_response()?;
        resp.write_all(INDEX_PAGE)?;
        Ok(())
    })?;
    let txc = tx.clone();
    server.fn_handler::<EspIOError, _>("/blink", Method::Get, move |req|{
        txc.send(Message::Blinker(blinker::BlinkerMessage::High));
        let mut resp = req.into_ok_response()?;
        resp.write_all("blinked".as_bytes())?;
        Ok(())
    })?;
    let txc = tx.clone();
    server.fn_handler::<EspIOError, _>("/text", Method::Post, move |mut req|{

        let len = req.header("Content-Length").unwrap_or("0");
        let len: usize = len.parse().unwrap_or(0); 
        let mut buf = vec![0u8; len];
        req.read_exact(&mut buf);
        let text = String::from_utf8(buf).unwrap_or("WRONG ENCODING".to_string());
        txc.send(Message::LedBoard(ledboard::Message::Text(text)));
        let mut resp = req.into_ok_response()?;
        resp.write_all("text drawing".as_bytes())?;
        Ok(())
    })?;
    let txc = tx.clone();
    server.fn_handler::<EspIOError, _>("/activate/relay1", Method::Post, move |req| {
        txc.send(Message::ActivateRelay(1));
        let mut resp = req.into_ok_response()?;
        resp.write_all("Relay 1 activated".as_bytes())?;

        Ok(())
    })?;
    let txc = tx.clone();
    server.fn_handler::<EspIOError, _>("/activate/relay2", Method::Post, move |req| {
        txc.send(Message::ActivateRelay(2));
        let mut resp = req.into_ok_response()?;
        resp.write_all("Relay 2 activated".as_bytes())?;

        Ok(())
    })?;
    let txc = tx.clone();
    server.fn_handler::<EspIOError, _>("/update", Method::Post, move |mut req| {
        let len = req.header("Content-Length").unwrap_or("0");
        let len: usize = len.parse().unwrap_or(0); 
        if len > 100 {
            req.into_status_response(413)?.write_all(b"Request too big")?;
            return Ok(());
        }
        let mut buf = vec![0u8; len];
        req.read_exact(&mut buf);
        let data = serde_json::from_slice::<msg::WifiCreds>(&buf).unwrap();
        txc.send(Message::ConnectWifi(data));
        req.into_ok_response()?.write_all(b"OK")?;
        Ok(())
    })?;

    info!("Server started");
    Ok(server)
}

struct SmartRelay {
    led: PinDriver<'static, AnyOutputPin, Output>,
    relay1: PinDriver<'static, AnyOutputPin, Output>,
    relay2: PinDriver<'static, AnyOutputPin, Output>,
    wifi: BlockingWifi<EspWifi<'static>>,
    server: EspHttpServer<'static>,
    flags: Arc<Flags>,
    nvs: EspNvs<NvsDefault>,
    tx: Sender<Message>,
    rx: Receiver<Message>,
    blinker: Blinker<Message>,
    ledboard: LedBoard,
}

impl SmartRelay {
    fn create() -> Result<Self> {
        let (tx,rx) = crossbeam::channel::unbounded();
        let partition = EspDefaultNvsPartition::take()?;
        let mut nvs = EspNvs::new(partition.clone(), NS, true)?;
        info!("Got namespace from default partition");
        let mut buf = vec![0u8;100];
        let wifi_creds = nvs.get_raw(WIFI_CREDS, &mut buf)?
        .map(|data|serde_json::from_slice::<msg::WifiCreds>(data));


        let peripherals = Peripherals::take()?;

        let led_pin: AnyOutputPin = peripherals.pins.gpio18.into();
        let mut led = PinDriver::output(led_pin)?;

        let relay1: AnyOutputPin = peripherals.pins.gpio14.into();
        let relay2: AnyOutputPin = peripherals.pins.gpio13.into();
        let mut  relay1 = PinDriver::output(relay1)?;
        relay1.set_high()?;
        let mut relay2 = PinDriver::output(relay2)?;
        relay2.set_high()?;
        
        led.set_high()?;
        FreeRtos::delay_ms(3000);
        led.set_low()?;
        info!("running led");
        let timer = EspTimerService::new()?;
        let ledboard = LedBoard::new(&timer, peripherals.rmt.channel2, peripherals.pins.gpio16)?;
        match Err(()) {// ledboard::start_led(peripherals.rmt.channel2, peripherals.pins.gpio16) {
            Ok(()) => println!("led is ok"),
            Err(e) => println!("err on led: {e:?}"),
        }
        let wifi = match wifi_creds {
            Some(Ok(creds)) => create_client_wifi(peripherals.modem, &creds.ssid, &creds.pass),
            Some(Err(e)) => {
                log::error!("Cannot parse wifi credentials: {:?}", e);
                nvs.remove(WIFI_CREDS)?;
                create_ap_wifi(peripherals.modem)
            },
            None => create_ap_wifi(peripherals.modem)
        }?;
        let flags = Arc::new(Flags::default());

        wifi.wait_netif_up()?;
        let server = start_server(tx.clone())?;
        let blinker = Blinker::new(peripherals.pins.gpio15.into(), &timer, tx.clone())?;
        let mut this = Self {led, relay1, relay2, wifi, nvs, flags, server, tx, rx, blinker, ledboard};
        Ok(this)
    }
    fn invoke_creds(flags: Arc<Flags>) -> Option<msg::WifiCreds> {
        let mut creds = flags.creds.lock().unwrap();
        match creds.clone() {
            Some(c) => {
                *creds = None;
                Some(c)
            },
            None => None
        }
    }
    fn process(&mut self, msg: Message) -> Result<()> {
        match msg {
            Message::ActivateRelay(_) => todo!(),
            Message::ConnectWifi(wifi_creds) => todo!(),
            Message::ShowText(_) => todo!(),
            Message::LedOn => todo!(),
            Message::LedOff => self.led.set_low()?,
            Message::Blinker(msg) => self.blinker.process(msg)?,
            Message::LedBoard(message) => self.ledboard.tx().send(message)?,
        }
        Ok(())
    }
    fn run(&mut self) -> Result<()> {
        loop {
            self.ledboard.process()?;
            match self.rx.try_recv() {
                Ok(msg) => self.process(msg),
                Err(TryRecvError::Empty) => {
                    FreeRtos::delay_ms(SLEEP_MS);
                    Ok(())
                },
                Err(TryRecvError::Disconnected) => break,
            }?;
        }

        let flags = self.flags.clone();
        loop {
            if let Some(c) = Self::invoke_creds(flags.clone()) {
                info!("received new wifi creds, esp will update and restart");
                if c.ssid.is_empty() {
                    self.nvs.remove(WIFI_CREDS)?;
                } else {
                    let buf = serde_json::to_vec(&c)?;
                    self.nvs.set_raw(WIFI_CREDS, &buf)?;
                }
                restart();
            }
            self.led.set_low()?;
        }
    }

}

fn enable_on_sec(pin: &mut PinDriver<'static, AnyOutputPin, Output>) -> Result<()> {
    pin.set_low()?;
    FreeRtos::delay_ms(1000);
    pin.set_high()?;
    Ok(())
}
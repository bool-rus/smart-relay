
use std::sync::{Arc, Mutex};
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
use esp_idf_svc::sys::{esp_pm_config_esp32s2_t, esp_pm_configure, esp_pm_get_configuration, ESP_ERR_INVALID_ARG, ESP_ERR_NOT_SUPPORTED, ESP_OK};
use esp_idf_svc::timer::{EspTimer, EspTimerService, Task};
use esp_idf_svc::wifi::{BlockingWifi, EspWifi};
use ledboard::{Color, LedBoard};
use log::info;
use msg::Message;

const SLEEP_MS: u32 = 11;
pub const MAX_BUFFER_SIZE: usize = 512;
const INDEX_PAGE: &'static [u8] = include_bytes!("index.html");

const STACK_SIZE: usize = 10240;
const NS: &str = "wifi-auth-data";
const WIFI_CREDS: &str = "wifi-creds";

mod ledboard;
mod msg;
mod font;
mod blinker;
mod config;
mod driver;

pub trait OkOrLog<T> {
    fn ok_or_log(self) -> Option<T>;
}

impl<T,E: std::fmt::Debug> OkOrLog<T> for std::result::Result<T,E> {
    fn ok_or_log(self) -> Option<T> {
        match self {
            Ok(obj) => return Some(obj),
            Err(e) => log::error!("{e:?}"),
        }
        None
    }
}

fn main() {
    esp_idf_svc::sys::link_patches();
    EspLogger::initialize_default();

    let mut conf = esp_pm_config_esp32s2_t { max_freq_mhz: 160, min_freq_mhz: 160, light_sleep_enable: false };
    let res = unsafe {
        let conf = &mut conf as *mut esp_pm_config_esp32s2_t;
        use core::ffi::c_void;
        esp_pm_get_configuration(conf as *mut c_void)
        //esp_pm_configure(conf as *const c_void)
    };
    match res {
        ESP_OK => info!("pm conigured {conf:?}!"),
        ESP_ERR_INVALID_ARG => log::error!("pm: invalid arg"),
        ESP_ERR_NOT_SUPPORTED => log::error!("pm: not supported"),
        e => log::error!("pm: unknown err {e}"),
    }

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

fn create_ap_wifi(hw: &mut BlockingWifi<EspWifi<'static>>) -> anyhow::Result<()> {
    use esp_idf_svc::wifi;
    let ssid = "smart-relay-ap";
    let pass = "booliscool";
    info!("Starting WiFi AP...");

    let wifi_configuration = wifi::Configuration::AccessPoint(wifi::AccessPointConfiguration {
        ssid: ssid.try_into().unwrap(),
        ssid_hidden: false,
        auth_method: wifi::AuthMethod::WPA2Personal,
        password: pass.try_into().unwrap(),
        channel: 11,
        ..Default::default()
    });
    hw.set_configuration(&wifi_configuration)?;
    hw.start()?;
    info!("WiFi AP started");
    Ok(())
}

fn invoke_creds<T: esp_idf_svc::nvs::NvsPartitionId>(nvs: &mut EspNvs<T>) -> Result<config::Wifi> {
    let mut buf = [0u8;100];
    let raw = nvs.get_raw(WIFI_CREDS, &mut buf)?;
    let raw = raw.ok_or(anyhow::anyhow!("no creds in nvs"))?;
    let wifi = serde_json::from_slice(raw)?;
    Ok(wifi)
}

fn create_wifi<T: esp_idf_svc::nvs::NvsPartitionId>(modem: Modem, nvs: &mut EspNvs<T>, reconnect: &EspTimer<'static>) -> anyhow::Result<BlockingWifi<EspWifi<'static>>> {
    info!("creating wifi");
    let sys_loop = EspSystemEventLoop::take()?;
    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(modem, sys_loop.clone(), None)?,
        sys_loop,
    )?;
    info!("wifi created");
    let mut buf = vec![0u8;100];
    if invoke_creds(nvs).ok_or_log().map(|creds|connect_to_wifi(&mut wifi, creds).ok_or_log()).flatten().is_none() {
        reconnect.after(Duration::from_secs(60)).ok_or_log();
        create_ap_wifi(&mut wifi)?
    }
    Ok(wifi)
}

fn connect_to_wifi(hw: &mut BlockingWifi<EspWifi<'static>>, creds: config::Wifi) -> Result<()> {
    use esp_idf_svc::wifi;
    let config::Wifi { ssid, pass } = creds;
    let wifi_configuration = wifi::Configuration::Client(wifi::ClientConfiguration {
        ssid: ssid.as_str().try_into().unwrap(),
        bssid: None,
        auth_method: wifi::AuthMethod::WPA2Personal,
        password: pass.as_str().try_into().unwrap(),
        channel: None,
        pmf_cfg: Default::default(),
        scan_method: wifi::ScanMethod::FastScan,
    });
    hw.set_configuration(&wifi_configuration)?;
    hw.start()?;
    hw.connect()?;
    info!("Wifi connected");
    Ok(())
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
        txc.send(Message::Blinker(blinker::Message::High)).ok_or_log();
        let mut resp = req.into_ok_response()?;
        resp.write_all("blinked".as_bytes())?;
        Ok(())
    })?;
    let txc = tx.clone();
    server.fn_handler::<EspIOError, _>("/color", Method::Post, move |mut req| {
        let len = req.header("Content-Length").unwrap_or("0");
        let len: usize = len.parse().unwrap_or(0); 
        if len > 100 {
            req.into_status_response(413)?.write_all(b"Request too big")?;
            return Ok(());
        }
        let mut buf = vec![0u8; len];
        req.read_exact(&mut buf).ok_or_log();
        let data = serde_json::from_slice::<Color>(&buf).unwrap();
        txc.send(Message::LedBoard(ledboard::Message::SetColor(data))).ok_or_log();
        req.into_ok_response()?.write_all(b"OK")?;
        Ok(())
    })?;
    let txc = tx.clone();

    server.fn_handler::<EspIOError, _>("/conf", Method::Post, move |mut req|{
        let len = req.header("Content-Length").unwrap_or("0");
        let len: usize = len.parse().unwrap_or(0); 
        if len > MAX_BUFFER_SIZE {
            req.into_status_response(413)?.write_all(b"Request too big")?;
            return Ok(());
        }
        let mut buf = vec![0u8; len];
        req.read_exact(&mut buf).ok_or_log();
        let data = match serde_json::from_slice::<config::Config>(&buf) {
            Ok(data) => data,
            Err(_) => {
                req.into_status_response(413)?.write_all(b"Wrong json").ok_or_log();
                return Ok(())
            }
        };
        if let Some(config::Led {color, move_period, 
            text, width, lt_delta, 
            move_step, font, space_width}) = data.led {
            use ledboard::Message::*;
            color.map(|c|txc.send(Message::LedBoard(SetColor(c))));
            move_period.map(|ms|txc.send(Message::LedBoard(SetMovePeriod(Duration::from_millis(ms)))));
            text.map(|text|txc.send(Message::LedBoard(Text(text))));
            width.map(|width|txc.send(Message::LedBoard(SetBoardWith(width))));
            lt_delta.map(|delta|txc.send(Message::LedBoard(LowTimingDelta(delta))));
            move_step.map(|step|txc.send(Message::LedBoard(SetMoveStep(step))));
            font.map(|font|txc.send(Message::LedBoard(SetFont(font))));
            space_width.map(|w|txc.send(Message::LedBoard(SetSpaceWidth(w))));
        };
        data.wifi.map(|wifi|txc.send(Message::SetWifi(wifi)));
        req.into_ok_response()?.write_all(b"OK")?;
        Ok(())
    })?;

    let txc = tx.clone();
    server.fn_handler::<EspIOError, _>("/text", Method::Post, move |mut req|{

        let len = req.header("Content-Length").unwrap_or("0");
        let len: usize = len.parse().unwrap_or(0); 
        if len > MAX_BUFFER_SIZE {
            req.into_status_response(413)?.write_all(b"Request too big")?;
            return Ok(());
        }
        let mut buf = vec![0u8; len];
        req.read_exact(&mut buf).ok_or_log();
        let text = String::from_utf8(buf).unwrap_or("WRONG ENCODING".to_string());
        txc.send(Message::LedBoard(ledboard::Message::Text(text))).ok_or_log();
        let mut resp = req.into_ok_response()?;
        resp.write_all("text drawing".as_bytes())?;
        Ok(())
    })?;
    let txc = tx.clone();
    server.fn_handler::<EspIOError, _>("/activate/relay1", Method::Post, move |req| {
        txc.send(Message::ActivateRelay(1)).ok_or_log();
        let mut resp = req.into_ok_response()?;
        resp.write_all("Relay 1 activated".as_bytes())?;

        Ok(())
    })?;
    let txc = tx.clone();
    server.fn_handler::<EspIOError, _>("/activate/relay2", Method::Post, move |req| {
        txc.send(Message::ActivateRelay(2)).ok_or_log();
        let mut resp = req.into_ok_response()?;
        resp.write_all("Relay 2 activated".as_bytes())?;

        Ok(())
    })?;
    let txc = tx.clone();
    server.fn_handler::<EspIOError, _>("/update", Method::Post, move |mut req| {
        let len = req.header("Content-Length").unwrap_or("0");
        let len: usize = len.parse().unwrap_or(0); 
        if len > MAX_BUFFER_SIZE {
            req.into_status_response(413)?.write_all(b"Request too big")?;
            return Ok(());
        }
        let mut buf = vec![0u8; len];
        req.read_exact(&mut buf).ok_or_log();
        let data = match serde_json::from_slice::<config::Wifi>(&buf) {
            Ok(data) => data,
            Err(e) => {
                req.into_status_response(413)?.write_all(b"Wrong json").ok_or_log();
                return Ok(())
            }
        };
        txc.send(Message::SetWifi(data)).ok_or_log();
        req.into_ok_response()?.write_all(b"OK")?;
        Ok(())
    })?;

    info!("Server started");
    Ok(server)
}

struct SmartRelay {
    relay1: PinDriver<'static, AnyOutputPin, Output>,
    relay2: PinDriver<'static, AnyOutputPin, Output>,
    wifi: BlockingWifi<EspWifi<'static>>,
    server: Option<EspHttpServer<'static>>,
    nvs: EspNvs<NvsDefault>,
    tx: Sender<Message>,
    rx: Receiver<Message>,
    blinker: Blinker,
    ledboard: LedBoard,
    reconnect_timer: EspTimer<'static>,
}

impl SmartRelay {
    fn create() -> Result<Self> {
        let (tx,rx) = crossbeam::channel::unbounded();
        let partition = EspDefaultNvsPartition::take()?;
        
        let mut nvs = EspNvs::new(partition.clone(), NS, true)?;
        info!("Got namespace from default partition");

        let peripherals = Peripherals::take()?;

        let relay1: AnyOutputPin = peripherals.pins.gpio14.into();
        let relay2: AnyOutputPin = peripherals.pins.gpio13.into();
        let mut  relay1 = PinDriver::output(relay1)?;
        relay1.set_high()?;
        let mut relay2 = PinDriver::output(relay2)?;
        relay2.set_high()?;

        info!("running led");
        let timer = EspTimerService::new()?;
        let txc = tx.clone();
        let reconnect_timer = timer.timer(move||{txc.send(Message::ConnectWifi).ok_or_log();})?;
        let wifi = create_wifi(peripherals.modem, &mut nvs, &reconnect_timer)?;

        wifi.wait_netif_up()?;
        let server = Some(start_server(tx.clone())?);
        let blinker = Blinker::new(&timer, peripherals.pins.gpio15.into())?;
        let ledboard = LedBoard::new(partition.clone(), &timer, peripherals.rmt.channel2, peripherals.pins.gpio16)?;
        let this = Self {relay1, relay2, wifi, nvs, server, tx, rx, blinker, ledboard, reconnect_timer};
        Ok(this)
    }
    fn process(&mut self, msg: Message) -> Result<()> {
        match msg {
            Message::ActivateRelay(_) => todo!(),
            Message::SetWifi(creds) => {
                if creds.ssid.is_empty() {
                    self.nvs.remove(WIFI_CREDS)?;
                    restart();
                } else {
                    let buf = serde_json::to_vec(&creds)?;
                    self.nvs.set_raw(WIFI_CREDS, &buf)?;
                }
                self.tx.send(Message::ConnectWifi)?;
            },
            Message::ConnectWifi => {self.connect_wifi()?;},
            Message::Blinker(msg) => self.blinker.tx().send(msg)?,
            Message::LedBoard(message) => self.ledboard.tx().send(message)?,
        }
        Ok(())
    }
    fn connect_wifi(&mut self) -> Result<()> {
        let creds = match invoke_creds(&mut self.nvs).ok_or_log() {
            Some(creds) => creds,
            None => return Ok(()),
        };
        self.server = None;
        self.wifi.stop()?;
        match connect_to_wifi(&mut self.wifi, creds) {
            Ok(_) => {},
            Err(e) => {
                log::error!("cannot connect to wifi: {e}\nstaritng Access Point...");
                create_ap_wifi(&mut self.wifi)?;
                self.reconnect_timer.after(Duration::from_secs(60)).ok_or_log();
            },
        }
        self.wifi.wait_netif_up()?;
        self.server = Some(start_server(self.tx.clone())?);
        Ok(())
    }
    fn run(&mut self) -> Result<()> {
        loop {
            self.ledboard.process()?;
            self.blinker.process()?;
            match self.rx.try_recv() {
                Ok(msg) => self.process(msg),
                Err(TryRecvError::Empty) => {
                    FreeRtos::delay_ms(SLEEP_MS);
                    Ok(())
                },
                Err(TryRecvError::Disconnected) => bail!("Channel diconnected"),
            }?;
        }
    }

}
use std::collections::HashMap;

use esp_idf_svc::hal::{delay::FreeRtos, gpio::OutputPin, peripheral::Peripheral, rmt::RmtChannel};
use ws2812_esp32_rmt_driver::*;
const LEDS_COUNT: usize = 512;


pub fn start_led(
    channel: impl Peripheral<P = impl RmtChannel> + 'static, 
    pin: impl Peripheral<P = impl OutputPin> + 'static
) -> anyhow::Result<()> {
    let mut driver = Ws2812Esp32RmtDriver::new(channel, pin)?;
    let fullsize = 8;
    let br = 0b0000101;
    let empty = std::iter::once(0).into_iter().cycle();
    let full = std::iter::once(br).into_iter().cycle();
    
    //driver.write_blocking(empty.clone().map(|_|[br,br,br]).flatten())?; 
    //FreeRtos::delay_ms(3000);  

    let font = make_font();
    loop {
    for i in 0..600 {
        let seq = make_sequence("с наступающим новым годом! Желаю счастья здоровья любви и удачи", &font, i)
            .chain(std::iter::once(0).cycle())
            .take(LEDS_COUNT);
        let seq = seq.into_iter().flat_map(move |p|[0,p*br,0]);
        driver.write(seq)?;
        FreeRtos::delay_ms(70);
    }}
    /* 
    driver.write_blocking([
        0,0,0, 0,0,0, 0,0,0, 0,0,0, 0,0,0, 0,0,0, 0,0,0, 0,0,0, 
        0,0,0, 0,0,0, 0,0,0, 0,0,0, 0,0,0, 0,0,0, 0,0,0, 0,0,0, 
        0,1,0,  
        ].into_iter())?;
    FreeRtos::delay_ms(5000);  
    */


    for i in 0..=LEDS_COUNT-fullsize {
        //driver.write_blocking(empty.clone().take(256).map(|_|[0,0,0]).flatten())?;
        //FreeRtos::delay_ms(70);
        let seq = empty.clone().take(i)
            .chain(full.clone().take(fullsize))
            .chain(empty.clone().take(LEDS_COUNT- i - fullsize))
            .flat_map(|x|[0,x,0]);
        log::info!("iteration {i}");
        driver.write_blocking(seq)?;
        FreeRtos::delay_ms(20);
    }
    driver.write_blocking(empty.take(512).map(|_|[0,0,0]).flatten())?;
    //driver.write_blocking([50,0,0, 0,50,0, 0,0,50].into_iter())?;
    Ok(())
}

fn make_sequence<'a> (text: &'a str, map: &'a HashMap<char, Vec<u8>>, offset: usize) -> impl Iterator<Item=u8> + 'static {
    let map = map.clone();
    let text: Vec<char> = text.chars().collect();
    let text = text.into_iter()
    .flat_map(
        move |c|map.get(&c).unwrap_or(&vec![0]).clone().into_iter().chain(std::iter::once(0))
    );
    std::iter::once(0).cycle().take(32).chain(text).skip(offset).enumerate()
    .map(|(n, it)|{
        let it = if n%2 ==0 {it} else {it.reverse_bits()};
        (0..u8::BITS).map(move |n|(it >> n) & 1)
    }).flatten()
}

fn make_font() -> HashMap<char, Vec<u8>> {
    let mut font = HashMap::new();
    font.insert('.', vec![
        0b10000000u8,
    ]);
    font.insert(',', vec![
        0b10000000,
        0b01000000,
    ]);
    font.insert(':', vec![
        0b10000100,
    ]);
    font.insert(';', vec![
        0b10000000,
        0b01000100,
    ]);
    font.insert('?', vec![
        0b00000100,
        0b10110010,
        0b00001100,
    ]);
    font.insert('(', vec![
        0b01111000,
        0b10000100,
    ]);
    font.insert(')', vec![
        0b10000100,
        0b01111000,
    ]);

    font.insert('а', vec![
        0b11110000,
        0b00101000,
        0b00101000,
        0b11110000,
    ].to_vec());
    font.insert('б', vec![
        0b11111000,
        0b10101000,
        0b11101000,
    ]);
    font.insert('в', vec![
        0b11111000,
        0b10101000,
        0b10101000,
        0b01010000,
    ]);
    font.insert('г', vec![
        0b11111000,
        0b00001000,
        0b00001000,
        0b00001000,
    ]);
    font.insert('д',vec![
        0b11000000,
        0b01111000,
        0b01001000,
        0b01111000,
        0b11000000,
    ]);
    font.insert('е',vec![
        0b11111000,
        0b10101000,
        0b10101000,
    ]);
    font.insert('ж',vec![
        0b10001000,
        0b01010000,
        0b11111000,
        0b01010000,
        0b10001000,
    ]);
    font.insert('з',vec![
        0b10001000,
        0b10101000,
        0b10101000,
        0b01010000,
    ]);
    font.insert('и',vec![
        0b11111000,
        0b01000000,
        0b00100000,
        0b11111000,
    ]);
    font.insert('й',vec![
        0b11111000,
        0b01000010,
        0b00100001,
        0b11111000,
    ]);
    font.insert('к',vec![
        0b11111000,
        0b00100000,
        0b01010000,
        0b10001000,
    ]);
    font.insert('л',vec![
        0b10000000,
        0b01110000,
        0b00001000,
        0b11111000,
    ]);
    font.insert('м',vec![
        0b11111000,
        0b00010000,
        0b00100000,
        0b00010000,
        0b11111000,
    ]);
    font.insert('н',vec![
        0b11111000,
        0b00100000,
        0b00100000,
        0b11111000,
    ]);
    font.insert('о',vec![
        0b01110000,
        0b10001000,
        0b10001000,
        0b01110000,
    ]);
    font.insert('п',vec![
        0b11111000,
        0b00001000,
        0b00001000,
        0b11111000,
    ]);
    font.insert('р',vec![
        0b11111000,
        0b00101000,
        0b00111000,
    ]);
    font.insert('с',vec![
        0b01110000,
        0b10001000,
        0b10001000,
        0b01010000,
    ]);
    font.insert('т',vec![
        0b00001000,
        0b11111000,
        0b00001000,
    ]);
    font.insert('у',vec![
        0b10011000,
        0b10100000,
        0b01111000,
    ]);
    font.insert('ф',vec![
        0b00010000,
        0b00101000,
        0b11111000,
        0b00101000,
        0b00010000,
    ]);
    font.insert('х',vec![
        0b11011000,
        0b00100000,
        0b11011000,
    ]);
    font.insert('ц',vec![
        0b11111000,
        0b10000000,
        0b11111000,
        0b10000000,
    ]);
    font.insert('ч',vec![
        0b00111000,
        0b00100000,
        0b11111000,
    ]);
    font.insert('ш',vec![
        0b11111000,
        0b10000000,
        0b11111000,
        0b10000000,
        0b11111000,
    ]);
    font.insert('щ',vec![
        0b11111000,
        0b10000000,
        0b11111000,
        0b10000000,
        0b11111000,
        0b10000000,
    ]);
    font.insert('ъ',vec![
        0b00001000,
        0b11111000,
        0b10100000,
        0b11100000,
    ]);
    font.insert('ы',vec![
        0b11111000,
        0b10100000,
        0b11100000,
        0,
        0b11111000,
    ]);
    font.insert('ь',vec![
        0b11111000,
        0b10100000,
        0b11100000,
    ]);
    font.insert('э',vec![
        0b01010000,
        0b10001000,
        0b10101000,
        0b01110000,
    ]);
    font.insert('ю',vec![
        0b11111000,
        0b00100000,
        0b11111000,
        0b10001000,
        0b11111000,
    ]);
    font.insert('я',vec![
        0b10110000,
        0b01101000,
        0b00101000,
        0b11111000,
    ]);
    font.insert(' ', vec![0]);
    font.insert('!', vec![0b10111110]);
    font.insert('А', vec![
        0b11111100,
        0b00010010,
        0b00010010,
        0b11111100,
    ]);
    font.insert('Б', vec![
        0b11111110,
        0b10010010,
        0b10010010,
        0b11110010,
    ]);
    font.insert('В',vec![
        0b11111110,
        0b10010010,
        0b10010010,
        0b01101100,
    ]);
    font.insert('Г', vec![
        0b11111110,
        0b00000010,
        0b00000010,
        0b00000110,
    ]);
    font.insert('Д', vec![
        0b11100000,
        0b00111110,
        0b00100010,
        0b00111110,
        0b11100000,
    ]);
    font.insert('Е', vec![
        0b11111110,
        0b10010010,
        0b10010010,
        0b10000010,
    ]);
    font.insert('Ж', vec![
        0b11000110,
        0b00101000,
        0b11111110,
        0b00101000,
        0b11000110,
    ]);
    font.insert('З', vec![
        0b01000100,
        0b10010010,
        0b10010010,
        0b01101100,
    ]);
    font.insert('И', vec![
        0b11111110,
        0b01000000,
        0b00100000,
        0b00010000,
        0b11111110,
    ]);
    font.insert('Й', vec![
        0b11111110,
        0b01000000,
        0b00100001,
        0b00010000,
        0b11111110,
    ]);
    font.insert('К', vec![
        0b11111110,
        0b00011000,
        0b00100100,
        0b11000010,
    ]);
    font.insert('Л', vec![
        0b10000000,
        0b11111110,
        0b00000010,
        0b00000010,
        0b11111110,
    ]);
    font
}

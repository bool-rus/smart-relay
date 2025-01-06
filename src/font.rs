use std::collections::HashMap;

pub struct Font {
    symbols: HashMap<char, u64>,
    default_symbol: u64,
}

impl Font {
    const SPACE_SKIP_BYTES: usize = 6;
    pub fn new() -> Self {
        let symbols = make_font();
        Self {symbols, default_symbol: 0}
    }
    pub fn render(&self, text: &str) -> Vec<u8> { //bit-mask
        text.chars().map(|c| {
            self.symbols.get(&c).unwrap_or(&self.default_symbol).to_ne_bytes()
        }).flat_map(|bytes|{
            //ищем первый ненулевой байт
            let mut skip = Self::SPACE_SKIP_BYTES;
            let mut i = 0;
            for b in bytes {
                if b > 0 {
                    skip = i;
                    break;
                }
                i+=1;
            }
            bytes.into_iter().skip(skip).chain(std::iter::once(0))
        }).collect()
    }
    pub fn set_char(&mut self, c: char, mask: Vec<u8>) {
        let mut x = [0u8;8];
        let mut i = 8-x.len();
        for b in mask {
            x[i]=b;
            i+=1;
        }
        self.symbols.insert(c, u64::from_ne_bytes(x));
    }
}


pub fn make_font() -> HashMap<char, u64> {
    let mut font = HashMap::new();
    font.insert('1', u64::from_ne_bytes([
        0,0,0,0,0,
        0b00010000,
        0b00001000,
        0b11111100,
    ]));
    font.insert('2', u64::from_ne_bytes([
        0,0,0,0,
        0b10001000,
        0b11000100,
        0b10100100,
        0b10011000,
    ]));
    font.insert('3', u64::from_ne_bytes([
        0,0,0,0,
        0b01001000,
        0b10000100,
        0b10010100,
        0b01101000,
    ]));
    font.insert('4', u64::from_ne_bytes([
        0,0,0,0,
        0b00111100,
        0b00100000,
        0b00100000,
        0b11111100,
    ]));
    font.insert('5', u64::from_ne_bytes([
        0,0,0,0,
        0b10011100,
        0b10010100,
        0b10010100,
        0b01100100,
    ]));
    font.insert('6', u64::from_ne_bytes([
        0,0,0,0,
        0b01111000,
        0b10010100,
        0b10010100,
        0b01100100,
    ]));
    font.insert('7', u64::from_ne_bytes([
        0,0,0,0,
        0b00000100,
        0b11100100,
        0b00010100,
        0b00001100,
    ]));
    font.insert('8', u64::from_ne_bytes([
        0,0,0,0,
        0b01101000,
        0b10010100,
        0b10010100,
        0b01101000,
    ]));
    font.insert('9', u64::from_ne_bytes([
        0,0,0,0,
        0b10011000,
        0b10100100,
        0b10100100,
        0b01111000,
    ]));
    font.insert('0', u64::from_ne_bytes([
        0,0,0,0,
        0b01111000,
        0b10100100,
        0b10010100,
        0b01111000,
    ]));
    font.insert('.', u64::from_ne_bytes([
        0,0,0,0,0,0,0,
        0b10000000u8,
    ]));
    font.insert(',', u64::from_ne_bytes([
        0,0,0,0,0,0,
        0b10000000,
        0b01000000,
    ]));
    font.insert(':', u64::from_ne_bytes([
        0,0,0,0,0,0,0,
        0b10000100,
    ]));
    font.insert(';', u64::from_ne_bytes([
        0,0,0,0,0,0,
        0b10000000,
        0b01000100,
    ]));
    font.insert('?', u64::from_ne_bytes([
        0,0,0,0,0,
        0b00000100,
        0b10110010,
        0b00001100,
    ]));
    font.insert('(', u64::from_ne_bytes([
        0,0,0,0,0,0,
        0b01111000,
        0b10000100,
    ]));
    font.insert(')', u64::from_ne_bytes([
        0,0,0,0,0,0,
        0b10000100,
        0b01111000,
    ]));
    font.insert('*', u64::from_ne_bytes([
        0,
        0b00010000,
        0b01010100,
        0b00111000,
        0b11101110,
        0b00111000,
        0b01010100,
        0b00010000,
    ]));

    font.insert('а', u64::from_ne_bytes([
        0,0,0,0,
        0b11110000,
        0b00101000,
        0b00101000,
        0b11110000,
    ]));
    font.insert('б', u64::from_ne_bytes([
        0,0,0,0,0,
        0b11111000,
        0b10101000,
        0b11101000,
    ]));
    font.insert('в', u64::from_ne_bytes([
        0,0,0,0,
        0b11111000,
        0b10101000,
        0b10101000,
        0b01010000,
    ]));
    font.insert('г', u64::from_ne_bytes([
        0,0,0,0,
        0b11111000,
        0b00001000,
        0b00001000,
        0b00001000,
    ]));
    font.insert('д', u64::from_ne_bytes([
        0,0,0,
        0b11000000,
        0b01111000,
        0b01001000,
        0b01111000,
        0b11000000,
    ]));
    font.insert('е', u64::from_ne_bytes([
        0,0,0,0,0,
        0b11111000,
        0b10101000,
        0b10101000,
    ]));
    font.insert('ж', u64::from_ne_bytes([
        0,0,0,
        0b10001000,
        0b01010000,
        0b11111000,
        0b01010000,
        0b10001000,
    ]));
    font.insert('з', u64::from_ne_bytes([
        0,0,0,0,
        0b10001000,
        0b10101000,
        0b10101000,
        0b01010000,
    ]));
    font.insert('и', u64::from_ne_bytes([
        0,0,0,0,
        0b11111000,
        0b01000000,
        0b00100000,
        0b11111000,
    ]));
    font.insert('й', u64::from_ne_bytes([
        0,0,0,0,
        0b11111000,
        0b01000010,
        0b00100001,
        0b11111000,
    ]));
    font.insert('к', u64::from_ne_bytes([
        0,0,0,0,
        0b11111000,
        0b00100000,
        0b01010000,
        0b10001000,
    ]));
    font.insert('л', u64::from_ne_bytes([
        0,0,0,0,
        0b10000000,
        0b01110000,
        0b00001000,
        0b11111000,
    ]));
    font.insert('м', u64::from_ne_bytes([
        0,0,0,
        0b11111000,
        0b00010000,
        0b00100000,
        0b00010000,
        0b11111000,
    ]));
    font.insert('н', u64::from_ne_bytes([
        0,0,0,0,
        0b11111000,
        0b00100000,
        0b00100000,
        0b11111000,
    ]));
    font.insert('о', u64::from_ne_bytes([
        0,0,0,0,
        0b01110000,
        0b10001000,
        0b10001000,
        0b01110000,
    ]));
    font.insert('п', u64::from_ne_bytes([
        0,0,0,0,
        0b11111000,
        0b00001000,
        0b00001000,
        0b11111000,
    ]));
    font.insert('р', u64::from_ne_bytes([
        0,0,0,0,0,
        0b11111000,
        0b00101000,
        0b00111000,
    ]));
    font.insert('с', u64::from_ne_bytes([
        0,0,0,0,
        0b01110000,
        0b10001000,
        0b10001000,
        0b01010000,
    ]));
    font.insert('т', u64::from_ne_bytes([
        0,0,0,0,0,
        0b00001000,
        0b11111000,
        0b00001000,
    ]));
    font.insert('у', u64::from_ne_bytes([
        0,0,0,0,0,
        0b10011000,
        0b10100000,
        0b01111000,
    ]));
    font.insert('ф', u64::from_ne_bytes([
        0,0,0,
        0b00010000,
        0b00101000,
        0b11111000,
        0b00101000,
        0b00010000,
    ]));
    font.insert('х', u64::from_ne_bytes([
        0,0,0,0,0,
        0b11011000,
        0b00100000,
        0b11011000,
    ]));
    font.insert('ц', u64::from_ne_bytes([
        0,0,0,0,
        0b11111000,
        0b10000000,
        0b11111000,
        0b10000000,
    ]));
    font.insert('ч', u64::from_ne_bytes([
        0,0,0,0,0,
        0b00111000,
        0b00100000,
        0b11111000,
    ]));
    font.insert('ш', u64::from_ne_bytes([
        0,0,0,
        0b11111000,
        0b10000000,
        0b11111000,
        0b10000000,
        0b11111000,
    ]));
    font.insert('щ', u64::from_ne_bytes([
        0,0,
        0b11111000,
        0b10000000,
        0b11111000,
        0b10000000,
        0b11111000,
        0b10000000,
    ]));
    font.insert('ъ', u64::from_ne_bytes([
        0,0,0,0,
        0b00001000,
        0b11111000,
        0b10100000,
        0b11100000,
    ]));
    font.insert('ы', u64::from_ne_bytes([
        0,0,0,
        0b11111000,
        0b10100000,
        0b11100000,
        0,
        0b11111000,
    ]));
    font.insert('ь', u64::from_ne_bytes([
        0,0,0,0,0,
        0b11111000,
        0b10100000,
        0b11100000,
    ]));
    font.insert('э', u64::from_ne_bytes([
        0,0,0,0,
        0b01010000,
        0b10001000,
        0b10101000,
        0b01110000,
    ]));
    font.insert('ю', u64::from_ne_bytes([
        0,0,0,
        0b11111000,
        0b00100000,
        0b11111000,
        0b10001000,
        0b11111000,
    ]));
    font.insert('я', u64::from_ne_bytes([
        0,0,0,0,
        0b10110000,
        0b01101000,
        0b00101000,
        0b11111000,
    ]));
    font.insert(' ', 0);
    font.insert('!', u64::from_ne_bytes([0,0,0,0,0,0,0,0b10111110]));
    font.insert('А', u64::from_ne_bytes([
        0,0,0,0,
        0b11111100,
        0b00010010,
        0b00010010,
        0b11111100,
    ]));
    font.insert('Б', u64::from_ne_bytes([
        0,0,0,0,
        0b11111110,
        0b10010010,
        0b10010010,
        0b11110010,
    ]));
    font.insert('В', u64::from_ne_bytes([
        0,0,0,0,
        0b11111110,
        0b10010010,
        0b10010010,
        0b01101100,
    ]));
    font.insert('Г', u64::from_ne_bytes([
        0,0,0,0,
        0b11111110,
        0b00000010,
        0b00000010,
        0b00000110,
    ]));
    font.insert('Д', u64::from_ne_bytes([
        0,0,0,
        0b11100000,
        0b00111110,
        0b00100010,
        0b00111110,
        0b11100000,
    ]));
    font.insert('Е', u64::from_ne_bytes([
        0,0,0,0,
        0b11111110,
        0b10010010,
        0b10010010,
        0b10000010,
    ]));
    font.insert('Ж', u64::from_ne_bytes([
        0,0,0,
        0b11000110,
        0b00101000,
        0b11111110,
        0b00101000,
        0b11000110,
    ]));
    font.insert('З', u64::from_ne_bytes([
        0,0,0,0,
        0b01000100,
        0b10010010,
        0b10010010,
        0b01101100,
    ]));
    font.insert('И', u64::from_ne_bytes([
        0,0,0,
        0b11111110,
        0b01000000,
        0b00100000,
        0b00010000,
        0b11111110,
    ]));
    font.insert('Й', u64::from_ne_bytes([
        0,0,0,
        0b11111110,
        0b01000000,
        0b00100001,
        0b00010000,
        0b11111110,
    ]));
    font.insert('К', u64::from_ne_bytes([
        0,0,0,0,
        0b11111110,
        0b00011000,
        0b00100100,
        0b11000010,
    ]));
    font.insert('Л', u64::from_ne_bytes([
        0,0,0,
        0b10000000,
        0b11111110,
        0b00000010,
        0b00000010,
        0b11111110,
    ]));
    font.insert('М', u64::from_ne_bytes([
        0,
        0b11111110,
        0b00000010,
        0b00000100,
        0b00011000,
        0b00000100,
        0b00000010,
        0b11111110,
    ]));
    font.insert('Н', u64::from_ne_bytes([
        0,0,0,
        0b11111110,
        0b00010000,
        0b00010000,
        0b00010000,
        0b11111110,
    ]));
    font.insert('О', u64::from_ne_bytes([
        0,0,0,
        0b01111100,
        0b10000010,
        0b10000010,
        0b10000010,
        0b01111100,
    ]));
    font.insert('П', u64::from_ne_bytes([
        0,0,0,
        0b11111110,
        0b00000010,
        0b00000010,
        0b00000010,
        0b11111110,
    ]));
    font.insert('Р', u64::from_ne_bytes([
        0,0,0,
        0b11111110,
        0b00100010,
        0b00100010,
        0b00100010,
        0b00011100,
    ]));
    font.insert('С', u64::from_ne_bytes([
        0,0,0,
        0b01111100,
        0b10000010,
        0b10000010,
        0b10000010,
        0b01000100,
    ]));
    font.insert('Т', u64::from_ne_bytes([
        0,0,0,
        0b00000010,
        0b00000010,
        0b11111110,
        0b00000010,
        0b00000010,
    ]));
    font.insert('У', u64::from_ne_bytes([
        0,0,0,
        0b10000010,
        0b01000100,
        0b00101000,
        0b00010000,
        0b00001110,
    ]));
    font.insert('Ф', u64::from_ne_bytes([
        0,0,0,
        0b00011100,
        0b00100010,
        0b11111110,
        0b00100010,
        0b00011100,
    ]));
    font.insert('Х', u64::from_ne_bytes([
        0,0,0,
        0b11000110,
        0b00101000,
        0b00010000,
        0b00101000,
        0b11000110,
    ]));
    font.insert('Ц', u64::from_ne_bytes([
        0,0,0,
        0b11111110,
        0b10000000,
        0b10000000,
        0b11111110,
        0b10000000,
    ]));
    font.insert('Ч', u64::from_ne_bytes([
        0,0,0,0,
        0b00001110,
        0b00010000,
        0b00010000,
        0b11111110,
    ]));
    font.insert('Ш', u64::from_ne_bytes([
        0,0,0,
        0b11111110,
        0b10000000,
        0b11111110,
        0b10000000,
        0b11111110,
    ]));
    font.insert('Щ', u64::from_ne_bytes([
        0,0,
        0b11111110,
        0b10000000,
        0b11111110,
        0b10000000,
        0b11111110,
        0b10000000,
    ]));
    font.insert('Ь', u64::from_ne_bytes([
        0,0,0,0,
        0b11111110,
        0b10010000,
        0b10010000,
        0b01100000,
    ]));
    font.insert('Ы', u64::from_ne_bytes([
        0,0,
        0b11111110,
        0b10010000,
        0b10010000,
        0b01100000,
        0b00000000,
        0b11111110,
    ]));
    font.insert('Ъ', u64::from_ne_bytes([
        0,0,0,
        0b00000010,
        0b11111110,
        0b10010000,
        0b10010000,
        0b01100000,
    ]));
    font.insert('Э', u64::from_ne_bytes([
        0,0,0,0,
        0b01000100,
        0b10010010,
        0b10010010,
        0b01111100,
    ]));
    font.insert('Ю', u64::from_ne_bytes([
        0,0,
        0b11111110,
        0b00010000,
        0b01111100,
        0b10000010,
        0b10000010,
        0b01111100,
    ]));
    font.insert('Я', u64::from_ne_bytes([
        0,0,0,0,
        0b10001100,
        0b01010010,
        0b00110010,
        0b11111110,
    ]));
    font
}

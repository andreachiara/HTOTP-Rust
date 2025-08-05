const H0: u32 = 0x67452301;
const H1: u32 = 0xefcdab89;
const H2: u32 = 0x98badcfe;
const H3: u32 = 0x10325476;
const H4: u32 = 0xc3d2e1f0;
const END_MSG: u8 = 0b10000000;
const K1: u32 = 0x5a827999;
const K2: u32 = 0x6ed9eba1;
const K3: u32 = 0x8f1bbcdc;
const K4: u32 = 0xca62c1d6;

#[derive(Debug)]
pub struct BlockOf16Words {
    words: [u32; 16],
}

impl std::fmt::Display for BlockOf16Words {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{:08x} {:08x} {:08x} {:08x}\n{:08x} {:08x} {:08x} {:08x}\n{:08x} {:08x} {:08x} {:08x}\n{:08x} {:08x} {:08x} {:08x}",
            self.words[0],
            self.words[1],
            self.words[2],
            self.words[3],
            self.words[4],
            self.words[5],
            self.words[6],
            self.words[7],
            self.words[8],
            self.words[9],
            self.words[10],
            self.words[11],
            self.words[12],
            self.words[13],
            self.words[14],
            self.words[15]
        )
    }
}

type VecOfBlocks = Vec<BlockOf16Words>;

pub struct SHA1Calc {
    h: [u32; 5],
    w: [u32; 80],
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
    m: VecOfBlocks,
    temp: u32,
}

impl SHA1Calc {
    fn new() -> Self {
        let empty_vec: Vec<BlockOf16Words> = Vec::new();
        SHA1Calc {
            h: [H0, H1, H2, H3, H4],
            m: empty_vec,
            w: [0; 80],
            a: 0,
            b: 0,
            c: 0,
            d: 0,
            e: 0,
            temp: 0,
        }
    }

    fn _init_h(&mut self) {
        self.h = [H0, H1, H2, H3, H4];
    }

    fn _init_w(&mut self) {
        self.w = [0; 80];
    }

    fn compute_block(&mut self, i: usize) -> [u32; 5] {
        //        self._init_w();
        for idx in 0..16 {
            self.w[idx] = self.m[i].words[idx];
        }
        //        println!("W: {:?}", self.w);
        for t in 16..=79 {
            let new_val_mi = self.w[t - 3] ^ self.w[t - 8] ^ self.w[t - 14] ^ self.w[t - 16];
            self.w[t] = S(1, new_val_mi);
        }
        self.a = self.h[0];
        self.b = self.h[1];
        self.c = self.h[2];
        self.d = self.h[3];
        self.e = self.h[4];

        for t in 0..80 {
            self.temp = S(5, self.a)
                .wrapping_add(f(t, self.b, self.c, self.d))
                .wrapping_add(self.e)
                .wrapping_add(self.w[t])
                .wrapping_add(get_k(t));
            self.e = self.d;
            self.d = self.c;
            self.c = S(30, self.b);
            self.b = self.a;
            self.a = self.temp;
        }
        self.h[0] = self.h[0].wrapping_add(self.a);
        self.h[1] = self.h[1].wrapping_add(self.b);
        self.h[2] = self.h[2].wrapping_add(self.c);
        self.h[3] = self.h[3].wrapping_add(self.d);
        self.h[4] = self.h[4].wrapping_add(self.e);

        return self.h;
    }
    pub fn compute_all(&mut self) -> [u32; 5] {
        for b in 0..self.m.len() {
            self.compute_block(b);
        }
        return self.h;
    }

    pub fn result(&self) -> [u32; 5] {
        return self.h;
    }
}

fn S(n: u8, x: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}

fn get_k(t: usize) -> u32 {
    match t {
        0..=19 => K1,
        20..=39 => K2,
        40..=59 => K3,
        _ => K4,
    }
}

fn f_1(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | ((b ^ 0xffffffff) & d)
}

fn f_2(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}
fn f_3(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (b & d) | (c & d)
}
fn f_4(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}

fn f(t: usize, b: u32, c: u32, d: u32) -> u32 {
    match t {
        0..=19 => f_1(b, c, d),
        20..=39 => f_2(b, c, d),
        40..=59 => f_3(b, c, d),
        _ => f_4(b, c, d),
    }
}

pub fn slice_to_word(slice: &[u8]) -> u32 {
    //    println!("Making a word out of the slice: {:?}", slice);
    let mut word: u32 = 0;
    for byte in 0..slice.len() {
        word |= u32::from(slice[byte]) << (24 - (8 * byte));
    }
    return word;
}

pub fn slice_to_fullblock(slice: &[u8]) -> BlockOf16Words {
    let mut block: BlockOf16Words = BlockOf16Words { words: [0; 16] };
    let mut word = 0;

    loop {
        let begin = word * 4;
        if begin >= slice.len() {
            break;
        }
        let end = if begin + 4 < slice.len() {
            begin + 4
        } else {
            slice.len()
        };
        block.words[word] = slice_to_word(&slice[begin..end]);
        // println!("s2lb: {:x}", block.words[word]);
        word += 1;
    }
    return block;
}

pub fn slice_to_lastblock(slice: &[u8]) -> BlockOf16Words {
    println!("last message block of len {}", slice.len());
    let mut block: BlockOf16Words = BlockOf16Words { words: [0; 16] };
    let mut word = 0;

    loop {
        let begin = word * 4;
        if begin >= slice.len() {
            break;
        }
        let end = if begin + 4 < slice.len() {
            begin + 4
        } else {
            slice.len()
        };
        block.words[word] = slice_to_word(&slice[begin..end]);
        //  println!("s2lb: {:x}", block.words[word]);
        word += 1;
    }

    return block;
}

impl From<&[u8]> for SHA1Calc {
    fn from(message: &[u8]) -> Self {
        let mut ret = SHA1Calc::new();
        ret.m.clear();

        let blocks_in_message = if message.len() % 64 == 0 {
            message.len() / 64
        } else if message.len() % 64 <= 55 {
            (message.len() / 64) + 1
        } else {
            (message.len() / 64) + 2
        };
        let message_len_bits = message.len() * 8;

        let mut idx: usize = 0;
        loop {
            let remaining = (message.len()).saturating_sub(idx);
            //  println!("remaining bytes: {}", remaining);
            if remaining == 0 {
                break;
            }
            let begin = idx;
            let end = if begin + 64 < message.len() {
                begin + 64
            } else {
                message.len()
            };
            println!(
                "Total: {} | Remaining: {} | begin: {} | end: {}",
                message.len(),
                remaining,
                begin,
                end
            );
            if remaining <= 55 {
                let mut lastbit_added: Vec<u8> = message[begin..end].to_vec();
                lastbit_added.push(END_MSG);
                //  println!("{:?}", lastbit_added);
                let mut lastblock = slice_to_lastblock(&lastbit_added[..]);
                lastblock.words[14] = u32::try_from((message_len_bits >> 32) & 0xffffffff).unwrap();
                lastblock.words[15] = u32::try_from(message_len_bits & 0xffffffff).unwrap();
                ret.m.push(lastblock);
                break;
            } else if remaining <= 63 {
                let mut lastbit_added: Vec<u8> = message[begin..end].to_vec();
                lastbit_added.push(END_MSG);
                // println!("{:?}", lastbit_added);
                let lastblock = slice_to_lastblock(&lastbit_added[..]);
                ret.m.push(lastblock);
                let mut lastblock = BlockOf16Words { words: [0; 16] };
                lastblock.words[14] = u32::try_from((message_len_bits >> 32) & 0xffffffff).unwrap();
                lastblock.words[15] = u32::try_from(message_len_bits & 0xffffffff).unwrap();
                ret.m.push(lastblock);
                break;
            } else {
                ret.m.push(slice_to_fullblock(&message[begin..end]));
            }
            idx += 64;
        }

        ret
    }
}

impl From<&str> for SHA1Calc {
    fn from(message_str: &str) -> Self {
        return SHA1Calc::from(message_str.as_bytes());
    }
}

pub fn to_hex_str(h: [u32; 5]) -> String {
    format!(
        "{:08x}{:08x}{:08x}{:08x}{:08x}",
        h[0], h[1], h[2], h[3], h[4]
    )
}

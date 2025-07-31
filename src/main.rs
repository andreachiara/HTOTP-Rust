/*
The variable names herein are mostly the same as the names in the RFC3174 spec, which defines this algorithm
https://www.rfc-editor.org/rfc/rfc3174
*/

use std::env;

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

struct BlockOf16Words {
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

struct SHA1Calc {
    h: [u32; 5],
    w: [u32; 80],
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
    m: Vec<BlockOf16Words>,
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

    fn compute_block(&mut self, i: usize) -> [u32; 5] {
        println!(
            "h0:{:x} h1:{:x} h2:{:x} h3:{:x} h4:{:x}",
            self.h[0], self.h[1], self.h[2], self.h[3], self.h[4]
        );
        for idx in 0..16 {
            self.w[idx] = self.m[i].words[idx];
        }
        for t in 16..=79 {
            let new_val_mi = self.w[t - 3] ^ self.w[t - 8] ^ self.w[t - 14] ^ self.w[t - 16];
            self.w[t] = S(1, new_val_mi);
        }
        self.a = H0;
        self.b = H1;
        self.c = H2;
        self.d = H3;
        self.e = H4;

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

impl From<&str> for SHA1Calc {
    fn from(message_str: &str) -> Self {
        let message: &[u8] = message_str.as_bytes();
        let mut ret = SHA1Calc::new();
        ret.m.clear();
        let mut tmp_word: u32 = 0;
        let mut tmp_block: BlockOf16Words = BlockOf16Words { words: [0; 16] };
        for idx in 0..message.len() + 1 {
            if idx == message.len() {
                tmp_word = tmp_word | u32::from(END_MSG) << ((3 - (idx % 4)) * 8)
            } else {
                println!(
                    "idx: {} | curr byte is: 0x{:x}",
                    idx,
                    u32::from(message[idx]) << ((3 - (idx % 4)) * 8)
                );
                tmp_word = tmp_word | u32::from(message[idx]) << ((3 - (idx % 4)) * 8)
            }
            println!("tmp word is: 0x{:x}", tmp_word);
            if (idx + 1) % 4 == 0 {
                println!("writing {} at {}", tmp_word, (idx / 4));
                tmp_block.words[(idx / 4)] = tmp_word;
                tmp_word = 0;
            }
            if idx % (16 * 4) == 0 && idx != 0 {
                println!("pushing at {}", idx % (16 * 4));
                ret.m.push(tmp_block);
                tmp_block = BlockOf16Words { words: [0; 16] };
            }
        }

        tmp_block.words[(message.len() / 4)] = tmp_word;
        let len_bits = message.len() * 8;
        let size_word_0 = u32::try_from((len_bits >> 32) & 0xffffffff).unwrap();
        let size_word_1 = u32::try_from((len_bits >> 0) & 0xffffffff).unwrap();
        tmp_block.words[14] = size_word_0;
        tmp_block.words[15] = size_word_1;

        println!("pushing last");
        ret.m.push(tmp_block);
        ret
    }
}

fn to_hex_str(h: [u32; 5]) -> String {
    format!(
        "{:08x}{:08x}{:08x}{:08x}{:08x}",
        h[0], h[1], h[2], h[3], h[4]
    )
}

fn main() {
    let args: Vec<String> = env::args().collect();
    //let test_string: &str = "hello world this is a long string";
    let test_string = args[1].as_str();
    let mut shatest: SHA1Calc = SHA1Calc::from(test_string);
    shatest.compute_block(0);
    println!("{}", shatest.m[0]);
    println!("{:?}", shatest.h);
    println!("{}", to_hex_str(shatest.h));
}

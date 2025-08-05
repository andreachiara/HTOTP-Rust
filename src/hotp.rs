const BASE_TEN: u32 = 10;

use crate::hmac::*;
use crate::sha1::*;

pub fn get_totp_from_hmac(hmac_w: [u32; 5], digits: u32) {
    let hmac = to_bytes(hmac_w);
    let offset = usize::from(hmac[19]) & 0xf;
    println!("HMAC is: {} | Offset is {}", to_hex_str(hmac_w), offset);
    let bytes_to_consider = &hmac[offset..offset + 4];
    println!(
        "considering bytes: 0x{:x} | 0x{:x} | 0x{:x} | 0x{:x}",
        bytes_to_consider[0], bytes_to_consider[1], bytes_to_consider[2], bytes_to_consider[3]
    );
    let word = slice_to_word(bytes_to_consider);
    println!(
        "bytes turned to: 0x{:x} = {}",
        word & 0x7fffffff,
        word & 0x7fffffff
    );
    let divider = BASE_TEN.pow(digits);
    let totp = (word & 0x7fffffff) % divider;
    println!("TOTP: {}", totp);
}

fn hex_str_to_bytes_le(s: &str) -> Vec<u8> {
    let mut ret_vec: Vec<u8> = vec![];
    let mut window_start = s.len();

    loop {
        if window_start < 2 {
            break;
        }
        ret_vec.push(u8::from_str_radix(&s[window_start - 2..window_start], 16).unwrap());
        window_start -= 2;
    }

    if window_start == 1 {
        ret_vec.push(u8::from_str_radix(&s[window_start - 1..window_start], 16).unwrap());
        println!("stray quartet: 0x{}", &s[window_start - 1..window_start]);
    }

    return ret_vec;
}
pub fn hex_str_to_bytes_be(s: &str) -> Vec<u8> {
    let mut ret_vec: Vec<u8> = vec![];
    let mut window_start = 0;

    loop {
        if window_start + 2 > s.len() {
            break;
        }
        ret_vec.push(u8::from_str_radix(&s[window_start..window_start + 2], 16).unwrap());
        window_start += 2;
    }

    if window_start != s.len() {
        println!("stray quartet: 0x{}", &s[window_start..window_start + 1]);
        ret_vec.push(u8::from_str_radix(&s[window_start..window_start + 1], 16).unwrap());
    }

    return ret_vec;
}

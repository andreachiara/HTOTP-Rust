/*
The variable names herein are mostly the same as the names in the RFC3174 spec, which defines this algorithm
https://www.rfc-editor.org/rfc/rfc3174
*/

use std::{
    env::{self},
    time::SystemTime,
};

mod hmac;
mod hotp;
mod sha1;

use crate::{hmac::*, hotp::*, sha1::*};

fn generate_hotp_full(key: &[u8], counter: &[u8]) {
    println!(
        "Generating HMAC from key: {:?} and counter: {:?}",
        key, counter
    );
    let hmac = hmac_compute(key, counter);
    //let hmac = hmac_compute(test_key, &counter_bytes[first_nonzero..]);
    get_totp_from_hmac(hmac, 6);
}

const BASE32_DIGITS: [u8; 33] = [
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
    89, 90, 50, 51, 52, 53, 54, 55, 61,
];

fn main() {
    let args: Vec<String> = env::args().collect();
    //let test_string: &str = "hello world this is a long string";
    let test_key = args[1].as_str();
    let test_period: u64 = args[2].parse().unwrap();
    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    println!("timestamp: {}", current_time);
    let counter: u64 = current_time / test_period;
    //let counter: u64 = test_period;
    let counter_bytes = counter.to_be_bytes(); // Must be be

    let mut last_nonzero: usize = 8;
    loop {
        last_nonzero -= 1;
        if counter_bytes[last_nonzero] != 0 {
            break;
        }
    }

    let mut first_nonzero: usize = 0;
    loop {
        if counter_bytes[first_nonzero] != 0 {
            break;
        }
        first_nonzero += 1;
    }

    println!(
        "counter {} = 0x{:x} -> bytes: {:?}",
        counter, counter, counter_bytes
    );

    generate_hotp_full(&hex_str_to_bytes_be(test_key), &counter_bytes);
}

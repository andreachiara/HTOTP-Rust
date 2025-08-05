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

fn main() {
    let args: Vec<String> = env::args().collect();
    //let test_string: &str = "hello world this is a long string";
    let test_key = args[1].as_str();
    let test_period: u64 = args[2].parse().unwrap();
    let test_msg = args[3].as_str();
    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    println!("timestamp: {}", current_time);
    //let counter: u64 = current_time / test_period;
    let counter: u64 = test_period;
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

    let hmac = hmac_compute(
        &hex_str_to_bytes_be(test_key),
        &hex_str_to_bytes_be(test_msg),
    );
    //let hmac = hmac_compute(test_key, &counter_bytes[first_nonzero..]);
    get_totp_from_hmac(hmac, 6);

    println!("{}", to_hex_str(hmac));
}

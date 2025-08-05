use crate::sha1::*;

pub fn to_bytes(h: [u32; 5]) -> [u8; 20] {
    let mut res: [u8; 20] = [0; 20];
    //println!("hex words: {}", to_hex_str(h));
    for i in 0..20 {
        res[i] = u8::try_from((h[i >> 2] >> 24 - ((i & 3) << 3)) & 0xff).unwrap();
        /*
                println!(
                    "word: 0x{:x} | pos: {} | byte: 0x{:x}",
                    h[i >> 2],
                    (i & 3) << 3,
                    res[i]
                );
        */
    }
    return res;
}

const HMAC_IPAD: u8 = 0x36;
const HMAC_OPAD: u8 = 0x5c;
const BLOCK_SIZE: usize = 64;
pub fn hmac_compute(key_str: &[u8], message_str: &[u8]) -> [u32; 5] {
    println!("message bytes: {:?}", message_str);
    let mut key_padding = vec![0; BLOCK_SIZE - key_str.len()];
    let mut key_padded = key_str.to_vec().clone();
    key_padded.append(&mut key_padding);
    let mut inner_block = key_padded.clone();
    for byte in inner_block.iter_mut() {
        *byte ^= HMAC_IPAD;
    }
    inner_block.append(&mut message_str.to_vec());
    let mut inner_sha = SHA1Calc::from(&inner_block[..]);
    inner_sha.compute_all();
    println!("Computed inner sha");
    let mut outer_block = key_padded.clone();
    for byte in outer_block.iter_mut() {
        *byte ^= HMAC_OPAD;
    }
    outer_block.append(&mut to_bytes(inner_sha.result()).to_vec());
    let mut outer_sha = SHA1Calc::from(&outer_block[..]);
    outer_sha.compute_all();
    return outer_sha.result();
}

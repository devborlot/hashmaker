//! WordPress phpass portable hash ($P$ / $H$).
//! Compatible with wp-includes/class-phpass.php (PasswordHash).

use md5::{Digest as _, Md5};
use rand_core::{OsRng, RngCore};

const ITOA64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn encode64(input: &[u8], count: usize) -> String {
    let mut output = String::new();
    let mut i = 0usize;

    loop {
        let mut value = input[i] as u32;
        i += 1;
        output.push(ITOA64[(value & 0x3f) as usize] as char);

        if i < count {
            value |= (input[i] as u32) << 8;
        }
        output.push(ITOA64[((value >> 6) & 0x3f) as usize] as char);

        if i >= count {
            break;
        }
        i += 1;

        if i < count {
            value |= (input[i] as u32) << 16;
        }
        output.push(ITOA64[((value >> 12) & 0x3f) as usize] as char);

        if i >= count {
            break;
        }
        i += 1;

        output.push(ITOA64[((value >> 18) & 0x3f) as usize] as char);

        if i >= count {
            break;
        }
    }

    output
}

fn itoa64_index(ch: u8) -> Option<usize> {
    ITOA64.iter().position(|&c| c == ch)
}

/// Generates a WordPress-compatible phpass portable hash (`$P$...`).
///
/// `iteration_count_log2` matches WordPress `PasswordHash($n, true)` — default 8,
/// which encodes as `$P$B` and runs 2^13 MD5 iterations.
pub fn hash_wordpress_phpass(password: &str, iteration_count_log2: u32) -> Result<String, String> {
    if password.len() > 4096 {
        return Err("password too long (max 4096)".into());
    }

    let log2 = iteration_count_log2.clamp(4, 31);
    let count_log2 = (log2 + 5).min(30) as u32;
    let count = 1u32 << count_log2;

    let mut random = [0u8; 6];
    OsRng.fill_bytes(&mut random);

    let mut setting = String::with_capacity(12);
    setting.push_str("$P$");
    setting.push(ITOA64[count_log2 as usize] as char);
    setting.push_str(&encode64(&random, 6));

    let salt = &setting[4..12];
    let hash = crypt_private(password, salt, count);

    Ok(format!("{}{}", &setting[..12], encode64(&hash, 16)))
}

fn crypt_private(password: &str, salt: &str, count: u32) -> [u8; 16] {
    let mut hash = Md5::digest(format!("{salt}{password}").into_bytes());

    for _ in 0..count {
        let mut hasher = Md5::new();
        hasher.update(hash);
        hasher.update(password.as_bytes());
        hash = hasher.finalize();
    }

    hash.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_known_vector() {
        // WordPress PasswordHash(8, true) — fixed salt via crypt_private path
        let setting = "$P$B55D6LjfHDkINU5wF.v2BuuzO0/XPk/";
        let salt = &setting[4..12];
        let count_log2 = itoa64_index(setting.as_bytes()[3]).unwrap() as u32;
        let count = 1u32 << count_log2;
        let hash = crypt_private("test", salt, count);
        let encoded = encode64(&hash, 16);
        assert_eq!(&setting[12..], encoded);
    }
}

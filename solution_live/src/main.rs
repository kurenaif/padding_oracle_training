/*
const DEBUG_KEY: [u8; 32] = [b'a'; 32];

fn decode_token(token_bytes: &[u8]) -> Vec<u8> {
    let (iv, ciphertext) = token_bytes.split_at(16);
    let cipher = openssl::symm::Cipher::aes_256_cbc();
    let mut dec =
        openssl::symm::Crypter::new(cipher, openssl::symm::Mode::Decrypt, &DEBUG_KEY, Some(iv))
            .unwrap();
    dec.pad(false);
    let mut buf = vec![0u8; ciphertext.len() + cipher.block_size()];
    dec.update(ciphertext, &mut buf).unwrap();
    dec.finalize(&mut buf).unwrap();
    let len = buf.len() - cipher.block_size();
    buf.truncate(len);
    buf
}*/

async fn check(token_bytes: &[u8]) -> String {
    let token_b64 = base64::encode_config(token_bytes, base64::URL_SAFE);
    let res = reqwest::get(format!("http://localhost:4567/check?token={token_b64}"))
        .await
        .unwrap();
    let bytes = res.bytes().await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn token() -> Vec<u8> {
    let res = reqwest::get("http://localhost:4567/token").await.unwrap();
    let token_b64 = res.bytes().await.unwrap();
    base64::decode_config(token_b64, base64::URL_SAFE).unwrap()
}

#[tokio::main]
async fn main() {
    let token = token().await;
    let len = token.len();
    let iter_count = 16;
    let block_count = len / 16;
    for block in 0..(block_count - 1) {
        let mut modified = token[..len - block * 16].to_vec();
        'outer: for iter in 0..iter_count {
            let offset = len - iter - ((block + 1) * 16) - 1;
            for c in (0u8..=255).rev() {
                modified[offset] = c ^ token[offset];
                let resp = check(&modified).await;
                if resp != "decrypt error" {
                    for k in 0..=iter {
                        modified[offset + k] ^= (iter as u8) + 1;
                        modified[offset + k] ^= (iter as u8) + 2;
                    }
                    continue 'outer;
                }
            }
            panic!("fallthrough");
        }
        let block_bytes: Vec<_> = token
            .iter()
            .zip(modified.iter())
            .skip(modified.len() - 16 - 16)
            .take(16)
            .map(|(t, m)| *m ^ 16 ^ *t ^ 1)
            .collect();
        println!("{:02x?}", block_bytes);
        println!("{}", String::from_utf8_lossy(&block_bytes));
    }
}

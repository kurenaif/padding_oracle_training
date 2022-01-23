use padding_oracle_attack::*;

#[tokio::main]
async fn main() {
    // message with no padding
    let m_nopad = r#"{"id":9,"admin":false,"flag":true}"#;
    // let m_nopad = r#"{"id":9,"admin":true}"#;

    let pad_len = 16 - m_nopad.len() % 16;
    // message bytes
    let mut m_bytes = Vec::with_capacity(m_nopad.len() + pad_len);
    m_bytes.extend(m_nopad.as_bytes());
    m_bytes.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    // ciphertext bytes
    let mut c_bytes_full = vec![0u8; m_bytes.len() + BLOCK_SIZE];
    let block_count = c_bytes_full.len() / BLOCK_SIZE;
    for block_count in (2..=block_count).rev() {
        let (c_bytes, _) = c_bytes_full.split_at_mut(block_count * BLOCK_SIZE);
        let (m_bytes, _) = m_bytes.split_at((block_count - 1) * BLOCK_SIZE);

        // temporal ciphertext to try checking
        let mut challenge_bytes = c_bytes.to_vec();

        let (_, c_prev_block, _) = c_bytes.split_last_2_blocks_mut(BLOCK_SIZE);
        let (_, m_last_block) = m_bytes.rsplit_at(BLOCK_SIZE);

        // decrypted block
        let mut d_block = vec![0u8; BLOCK_SIZE];
        'outer: for pad_len in 1..=BLOCK_SIZE {
            let pad_start = BLOCK_SIZE - pad_len;

            for seq in (0u8..=255).rev() {
                let (_, challenge_prev_block, _) =
                    challenge_bytes.split_last_2_blocks_mut(BLOCK_SIZE);

                // fill padding bytes using partially revealed d_block
                for (c_pad_byte, d) in challenge_prev_block[pad_start + 1..]
                    .iter_mut()
                    .zip(d_block[pad_start + 1..].iter())
                {
                    *c_pad_byte = *d ^ pad_len as u8;
                }

                let challenge = seq ^ c_prev_block[pad_start];
                challenge_prev_block[pad_start] = challenge;

                let resp = check(&challenge_bytes).await;
                if resp != "decrypt error" {
                    // a byte of d_block was revealed
                    d_block[pad_start] = challenge ^ pad_len as u8;
                    continue 'outer;
                }
            }
            panic!("failed to reveal decrypted block");
        }
        // d_block has been fully revealed
        // so you can make a ciphertext block for arbitrary message
        for (c, (&d, &m)) in c_prev_block
            .iter_mut()
            .zip(d_block.iter().zip(m_last_block.iter()))
        {
            *c = d ^ m;
        }
    }
    let token = base64::encode_config(&c_bytes_full, base64::URL_SAFE);
    println!("======== TAMPERED ========");
    println!("TOKEN: {}", token);
    println!("==========================");
}

use padding_oracle_attack::*;

#[tokio::main]
async fn main() {
    // ciphertext bytes
    let c_bytes = token().await;
    let block_count = c_bytes.len() / BLOCK_SIZE;
    // message(plaintext) bytes
    let mut m_bytes = vec![0u8; c_bytes.len() - BLOCK_SIZE];
    for block_count in (2..=block_count).rev() {
        let (c_bytes, _) = c_bytes.split_at(block_count * BLOCK_SIZE);
        let (revealed_bytes, _) = m_bytes.split_at_mut((block_count - 1) * BLOCK_SIZE);

        // temporal ciphertext to try checking
        let mut challenge_bytes = c_bytes.to_vec();

        let (_, c_prev_block, _) = c_bytes.split_last_2_blocks(BLOCK_SIZE);
        let (_, revealed_last_block) = revealed_bytes.rsplit_at_mut(BLOCK_SIZE);

        // decrypted block
        let mut d_block = vec![0u8; BLOCK_SIZE];
        'outer: for pad_len in 1..=BLOCK_SIZE {
            let pad_start = BLOCK_SIZE - pad_len;

            for seq in (0u8..=255).rev() {
                let (_, challenge_prev_block, _) =
                    challenge_bytes.split_last_2_blocks_mut(BLOCK_SIZE);

                // fill the padding bytes using partially revealed d_block
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
        // so you can reveal the message block
        for (r, (&c, &d)) in revealed_last_block
            .iter_mut()
            .zip(c_prev_block.iter().zip(d_block.iter()))
        {
            *r = c ^ d;
        }
    }
    println!("======== REVEALED ========");
    println!("{:02x?}", &m_bytes);
    println!("{}", String::from_utf8_lossy(&m_bytes));
    println!("==========================");
}

pub const BLOCK_SIZE: usize = 16;

pub async fn check(token_bytes: &[u8]) -> String {
    let token_b64 = base64::encode_config(token_bytes, base64::URL_SAFE);
    let res = reqwest::get(format!("http://localhost:4567/check?token={token_b64}"))
        .await
        .unwrap();
    let bytes = res.bytes().await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

pub async fn token() -> Vec<u8> {
    let res = reqwest::get("http://localhost:4567/token").await.unwrap();
    let token_b64 = res.bytes().await.unwrap();
    base64::decode_config(token_b64, base64::URL_SAFE).unwrap()
}

pub trait RSplitAt<T> {
    fn rsplit_at(&self, rmid: usize) -> (&[T], &[T]);
}

impl<T> RSplitAt<T> for [T] {
    fn rsplit_at(&self, rmid: usize) -> (&[T], &[T]) {
        self.split_at(self.len() - rmid)
    }
}

pub trait RSplitAtMut<T>: AsMut<[T]> {
    fn rsplit_at_mut(&mut self, rmid: usize) -> (&mut [T], &mut [T]);
}

impl<T> RSplitAtMut<T> for [T] {
    fn rsplit_at_mut(&mut self, rmid: usize) -> (&mut [T], &mut [T]) {
        let len = self.as_mut().len();
        self.as_mut().split_at_mut(len - rmid)
    }
}

pub trait SplitLast2Blocks<T>: RSplitAt<T> {
    fn split_last_2_blocks(&self, block_size: usize) -> (&[T], &[T], &[T]) {
        let (head, last_block) = self.rsplit_at(block_size);
        let (head, prev_block) = head.rsplit_at(block_size);
        (head, prev_block, last_block)
    }
}

impl<T, S: RSplitAt<T> + ?Sized> SplitLast2Blocks<T> for S {}

pub trait SplitLast2BlocksMut<T>: RSplitAtMut<T> {
    fn split_last_2_blocks_mut(&mut self, block_size: usize) -> (&mut [T], &mut [T], &mut [T]) {
        let (head, last_block) = self.rsplit_at_mut(block_size);
        let (head, prev_block) = head.rsplit_at_mut(block_size);
        (head, prev_block, last_block)
    }
}

impl<T, S: RSplitAtMut<T> + ?Sized> SplitLast2BlocksMut<T> for S {}

pub mod debug {
    use super::BLOCK_SIZE;

    const DEBUG_KEY: [u8; 32] = [b'a'; 32];

    pub fn decode_token(token_bytes: &[u8]) -> Vec<u8> {
        let (iv, ciphertext) = token_bytes.split_at(BLOCK_SIZE);
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
    }
}

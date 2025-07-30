use aes_gcm::{aead::{Aead}, Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use uuid::Uuid;
use std::time::{SystemTime, UNIX_EPOCH};

type AesKey = [u8; 32];

#[derive(Debug)]
struct BlockChain {
    blocks: Vec<Block>,
    difficulty: usize,
}
impl BlockChain {
    pub fn new() -> Self {
        let difficulty = 3;
        Self {
            blocks: vec![Self::genesis(difficulty)],
            difficulty,
        }
    }

    fn genesis(difficulty: usize) -> Block {
        let mut genesis_block = Block::new(NodeData::empty(), "__GENESIS".into());
        genesis_block.mine_block(difficulty);
        genesis_block
    }

    pub fn add_block(&mut self, data: NodeData) {
        let last_block = self.blocks.last().unwrap();
        let mut new_block = Block::new(data, last_block.hash.clone());
        new_block.mine_block(self.difficulty);
        self.blocks.push(new_block);
    }

    pub fn is_valid(&self) -> bool {
        for i in 1..self.blocks.len() {
            let current = &self.blocks[i];
            let previous = &self.blocks[i - 1];

            let recalculated_hash = Block::calculate_hash(
                current.id,
                current.timestamp,
                &current.node,
                &current.previous_hash,
                current.nonce,
            );

            if current.hash != recalculated_hash {
                return false;
            }

            if current.previous_hash != previous.hash {
                return false;
            }

            if !current.hash.starts_with(&"0".repeat(self.difficulty)) {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone)]
struct EncryptedDEKRef {
    version: u32,
    encypted_dek: Vec<u8>,
    created_at: u64,
}

#[derive(Debug, Clone)]
struct NodeData {
    identifier: u64,
    data: Vec<u8>,
    dek_refs: Vec<EncryptedDEKRef>,
}

impl NodeData {
    pub fn new(identifier: u64, data: Vec<u8>, kek: &AesKey) -> Self {
        let dek = Self::generate_dek();
        let (ciphertext, _nonce) = Self::encrypt_data(&data, &dek);

        Self {
            identifier,
            dek_refs: vec![],
            data: ciphertext
        }
    }

    pub fn empty() -> Self {
        Self {
            identifier: 0,
            data: "GnosisDB Genesis Block".as_bytes().to_vec(),
            dek_refs: vec![],
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.append(&mut self.identifier.to_le_bytes().to_vec());
        bytes.append(&mut self.data.clone());
        bytes
    }

    pub fn checksum(&self) -> String {
        let mut hasher = Sha512::new();
        hasher.update(self.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    fn generate_dek() -> AesKey {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }
    
    fn encrypt_data(plain: &[u8], dek: &AesKey) -> (Vec<u8>, [u8; 12]) {
        let cipher = Aes256Gcm::new_from_slice(dek).unwrap();
        let nonce = rand::random::<[u8; 12]>();
        let ciphertext = cipher.encrypt(&Nonce::from_slice(&nonce), plain).unwrap();
        (ciphertext, nonce)
    }

    pub fn decrypt_data(&self, nonce: &[u8;12], dek: &AesKey) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(dek).unwrap();
        cipher.decrypt(nonce.into(), self.data.as_slice()).unwrap()
    }


}

#[derive(Debug, Clone)]
struct Block {
    id: Uuid,
    timestamp: u128,
    // checksum for mutable node data
    checksum: String,
    node: NodeData,
    previous_hash: String,
    nonce: u64,
    hash: String,
}

impl Block {
    pub fn new(node: NodeData, previous_hash: String) -> Self {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        Self {
            id: Uuid::new_v4(),
            timestamp,
            checksum: node.checksum(),
            node,
            previous_hash,
            nonce: 0,
            hash: String::new(),
        }
    }

    fn calculate_hash(id: Uuid, timestamp: u128, data: &NodeData, previous_hash: &str, nonce: u64) -> String {
        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        hasher.update(timestamp.to_string());
        hasher.update(data.as_bytes());
        hasher.update(previous_hash);
        hasher.update(nonce.to_string());
        format!("{:x}", hasher.finalize())
    }

    fn mine_block(&mut self, difficulty: usize) {
        let target = "0".repeat(difficulty);
        let timestamp1 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        while !self.hash.starts_with(&target) {
            self.nonce += 1;
            self.hash = Block::calculate_hash(self.id,
                self.timestamp,
                &self.node,
                &self.previous_hash,
                self.nonce
            );
        }
        let timestamp2 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        let time = timestamp2 - timestamp1;
        println!("Block mined in {time}: {}",self.hash);
    }
}

fn main() {
    let mut chain = BlockChain::new();
    let kek = NodeData::generate_dek();
    chain.add_block(NodeData::new(1, vec![], &kek));
    println!("The chain validity is {}.",chain.is_valid())
}

//use ark_ec::models::{short_weierstrass_jacobian::GroupAffine as SWAffine, SWModelParameters};
use ark_ec::PairingEngine;
use ark_ff::{Field, PrimeField};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::marlin::marlin_pc::MarlinKZG10;
use ark_poly_commit::{Polynomial, PolynomialCommitment};

use sha2::{Sha256, Digest};

// hash function (SHA-256 most likely)
pub fn hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// Node structure
pub struct Node {
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
    pub children: Vec<Node>,
}

impl Node {
    pub fn new(key: Vec<u8>) -> Self {
        Node {
            key,
            value: None,
            children: Vec::new(),
        }
    }
    // insert a key-value pair into the trie but in a sorted manner so retrieval will be quicker
    // downside? insertion will be slower
    pub fn insert(&mut self, mut key: Vec<u8>, value: Vec<u8>) {
        if key.is_empty() {
            self.value = Some(value);
            return;
        }

        let prefix = key.remove(0); // Take the first byte of the key as prefix
        let position = self.children.binary_search_by(|child| child.key.cmp(&vec![prefix]));
        
        match position {
            Ok(index) => {
                self.children[index].insert(key, value);
            },
            Err(index) => {
                let mut new_node = Node::new(vec![prefix]);
                new_node.insert(key, value);
                self.children.insert(index, new_node);
            }
        }
    }
}

// VerkleTree structure
pub struct VerkleTree {
    pub root: Node,
}
 
impl VerkleTree {
    pub fn new(initial_key: Option<Vec<u8>>) -> Self {
        VerkleTree {
            root: Node::new(initial_key.unwrap_or_else(Vec::new)),
        }
    }
    // TODO: Implement methods for VerkleTree (like commitment)
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
        // start at the root and insert the first key value
        self.root.insert(key, value);

    }
}

// make it follow trie structure
// prefix will be the hash

// impl VerkleTree{
//     // functions 
//     // create root
//     // insert as children
//     // commitment
//     // compute commitment
// }
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
    value: Option<Vec<u8>>,
    children: Vec<Node>,
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
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {

        // position to insert the new node
        // use binary sort because it is sorted so it will be faster
        let pos = self.children.binary_search_by(|node| node.key.cmp(&key));

        match pos {
            // check if key already exists and if it does then we update the value at that index
            Ok(index) => {
                self.children[index].value = Some(value);
            },
            // if key does not exist then we insert the new node
            Err(index) => {
                let new_node = Node {
                    key: key,
                    value: Some(value),
                    children: Vec::new(),
                };
                self.children.insert(index, new_node);
            }
        }
    }

    // TODO: Implement trie operations for Node (like insertion)
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

// verkle tree structure 
// make it follow trie structure
// prefix will be the hash

// impl VerkleTree{
//     // functions 
//     // create root
//     // insert as children
//     // commitment
//     // compute commitment
// }
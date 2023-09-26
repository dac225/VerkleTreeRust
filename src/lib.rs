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

// lets set a fixed width of 256 bits (similar to vitalik's implementation)
const MAX_CHILDREN: usize = 256;

// Node structure
pub struct Node {
    pub key: Vec<u8>, // This key will now store the hashed prefix.
    pub value: Option<Vec<u8>>,
    pub children: Vec<Node>,
}

impl Node {
    pub fn new(key: Vec<u8>) -> Self {
        Node {
            key: hash(&key), // The passed key is hashed during node creation.
            value: None,
            children: Vec::new(),
        }
    }
    // NEXT STEPS:
    // make it so when the 257th item gets added then adding another child will force a restructure.
    // what should happen?
    // an internal node gets created and redistributes the children across nodes (not a leaf)
    // similar to how b-trees split nodes when they exceed their maximum capcacity 
    pub fn insert(&mut self, mut key: Vec<u8>, value: Vec<u8>) {
        if key.is_empty() {
            self.value = Some(value);
            return;
        }

        let prefix = key.remove(0); // Take the first byte of the key as prefix
        let hashed_prefix = hash(&vec![prefix]); // Hash the prefix before comparison.

        let position = self.children.binary_search_by(|child| child.key.cmp(&hashed_prefix));

        match position {
            Ok(index) => {
                self.children[index].insert(key, value);
            },
            Err(index) => {
                // Before inserting a new node, ensure we haven't exceeded max width.
                if self.children.len() < MAX_CHILDREN {
                    let mut new_node = Node::new(vec![prefix]);
                    new_node.insert(key, value);
                    self.children.insert(index, new_node);
                } else {
                    // Here you might want to handle the error or panic.
                    panic!("Exceeded maximum width!");
                }
            }
        }
    }
}

pub struct VerkleTree {
    pub root: Node,
}

impl VerkleTree {
    pub fn new(initial_key: Option<Vec<u8>>) -> Self {
        VerkleTree {
            root: Node::new(initial_key.unwrap_or_else(Vec::new)),
        }
    }

    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
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
use ark_ec::models::{short_weierstrass_jacobian::GroupAffine as SWAffine, SWModelParameters};
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


//One node with optional value
struct Node {
    key: Vec<u8>,
    value: Option<Vec<u8>>,
    children: Vec<Node>,
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
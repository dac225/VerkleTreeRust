use ark_ec::models::{short_weierstrass_jacobian::GroupAffine as SWAffine, SWModelParameters};
use ark_ec::PairingEngine;
use ark_ff::{Field, PrimeField};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::marlin::marlin_pc::MarlinKZG10;
use ark_poly_commit::{Polynomial, PolynomialCommitment};

// hash function (SHA-256 most likely)
fn hash(){

}

struct iNode { //intermediate Node
    key : String,
    children : Vec<vNode>
}

struct lNode { // leaf node
    key: String, 
    value: String
}

// verkle nodes
enum vNode {
    // children
    // hash? (key)
    key(String),
    children(Vec<vNode>),
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
use ark_ec::PairingEngine;
use ark_poly::UVPolynomial;
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::marlin::marlin_pc::MarlinKZG10;
use ark_poly_commit::PolynomialCommitment;
use ark_bls12_381::Bls12_381;
use rand::Rng;
use sha2::{Sha256, Digest};

// Assuming VerkleTreeRust is the name of your module
use VerkleTreeRust::VerkleTree;

fn main() {
    let mut rng = rand::thread_rng();
    let degree = 256;

    // Type annotations for MarlinKZG10 and DensePolynomial
    type Fr = <Bls12_381 as PairingEngine>::Fr;
    type Poly = DensePolynomial<Fr>;
    type KZG10 = MarlinKZG10<Bls12_381, Poly>;

    let params = KZG10::setup(degree, None, &mut rng).unwrap();
    let (committer_key, verifier_key) = KZG10::trim(&params, degree, 0, None).unwrap();

    let depth = 40; // Adjust as needed
    let branching_factor = 256; // Adjust as needed

    // Create the VerkleTree
    let mut tree = VerkleTree {
        root: VerkleTreeRust::Node::new(vec![], branching_factor, 0), // Initialize depth to 0
        params: (params, committer_key, verifier_key),
        max_depth: depth,
    };
    println!("Created VerkleTree with depth {}, branching factor {}", depth, branching_factor);

    let wallet_address = "4cce";
    let key_wallet = hex::decode(wallet_address).expect("Failed to decode hex string");
    
    // Insert the wallet address and its associated value into the tree
    tree.insert(key_wallet.clone(), vec![13, 14, 15]);
    println!("Inserted wallet address \"{}\" with value {:?}", wallet_address, vec![13, 14, 15]);

    let wallet_address2 = "9dcd";
    let key_wallet2 = hex::decode(wallet_address2).expect("Failed to decode hex string");
    
    // Insert the wallet address and its associated value into the tree
    tree.insert(key_wallet2.clone(), vec![14, 15, 16]);
    println!("Inserted wallet address \"{}\" with value {:?}", wallet_address2, vec![14, 15, 16]);

    let retrieved_value = tree.get(key_wallet);
    match retrieved_value {
        Some(value) => println!("Retrieved value for wallet address {}: {:?}", wallet_address, value),
        None => println!("No value found for wallet address {}", wallet_address),
    }
    
    // Retrieve the value associated with the wallet address
    let retrieved_value2 = tree.get(key_wallet2);
    match retrieved_value2 {
        Some(value) => println!("Retrieved value for wallet address {}: {:?}", wallet_address2, value),
        None => println!("No value found for wallet address {}", wallet_address2),
    }

    // Uncomment the line below if you want to print the tree structure
    // tree.print_tree();

    // Call set_commitments
    if let Err(e) = tree.set_commitments() {
        eprintln!("Error setting commitments: {:?}", e);
    } else {
        println!("Commitments set successfully.");
    }
}

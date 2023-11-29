use ark_ec::PairingEngine;
use ark_poly::UVPolynomial;
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::marlin::marlin_pc::MarlinKZG10;
use ark_poly_commit::PolynomialCommitment;
use ark_bls12_381::Bls12_381;
use rand::Rng;
use sha2::{Sha256, Digest};
use hex;

use VerkleTreeRust::VerkleTree;

fn main() {
    let mut rng = rand::thread_rng();
    let degree = 256;

    type Fr = <Bls12_381 as PairingEngine>::Fr;
    type Poly = DensePolynomial<Fr>;
    type KZG10 = MarlinKZG10<Bls12_381, Poly>;

    let params = KZG10::setup(degree, None, &mut rng).unwrap();
    let (committer_key, verifier_key) = KZG10::trim(&params, degree, 0, None).unwrap();

    let depth = 40;
    let branching_factor = 256;

    let mut tree = VerkleTree {
        root: VerkleTreeRust::Node::new(vec![], branching_factor, 0),
        params: (params, committer_key, verifier_key),
        max_depth: depth,
    };
    println!("Created VerkleTree with depth {}, branching factor {}", depth, branching_factor);

    // Inserting values
    let wallet_address = "4cce";
    let key_wallet = hex::decode(wallet_address).expect("Failed to decode hex string");
    tree.insert(key_wallet.clone(), vec![13, 14, 15]);
    println!("Inserted wallet address \"{}\" with value {:?}", wallet_address, vec![13, 14, 15]);

    let wallet_address2 = "9dcd";
    let key_wallet2 = hex::decode(wallet_address2).expect("Failed to decode hex string");
    tree.insert(key_wallet2.clone(), vec![14, 15, 16]);
    println!("Inserted wallet address \"{}\" with value {:?}", wallet_address2, vec![14, 15, 16]);

    let retrieved_value = tree.get(key_wallet.clone());
    match retrieved_value {
        Some(value) => println!("Retrieved value for wallet address {}: {:?}", wallet_address, value),
        None => println!("No value found for wallet address {}", wallet_address),
    }
    
    let retrieved_value2 = tree.get(key_wallet2.clone());
    match retrieved_value2 {
        Some(value) => println!("Retrieved value for wallet address {}: {:?}", wallet_address2, value),
        None => println!("No value found for wallet address {}", wallet_address2),
    }

    // Uncomment to print the tree structure
    // tree.print_tree();

    // Setting and checking commitments
    if let Err(e) = tree.set_commitments() {
        eprintln!("Error setting commitments: {:?}", e);
    } else {
        println!("Commitments set successfully.");
    }

    tree.print_commitments();

    let commitments_are_valid = tree.check_commitments();
    println!("All commitments in the tree are valid: {}", commitments_are_valid);

    // Test the verification for specific keys and generate proofs
    let keys_to_verify = vec![key_wallet, key_wallet2];
    for key in keys_to_verify {
        // Verify the path for the key
        let result = tree.verify_path(key.clone());
        println!("Verification for key {:?}: {}", hex::encode(&key), result);

        // Generate and display the proof for the key
        if let Some(proof) = tree.generate_proof_for_key(&key) {
            println!("Proof for key {:?}: {:?}", hex::encode(&key), proof);
        } else {
            println!("No proof generated for key {:?}", hex::encode(&key));
        }
    }
}

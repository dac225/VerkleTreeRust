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

    // Create a VerkleTree with committer_key and verifier_key
    let mut tree = VerkleTree::new(130, 256)
        .expect("Failed to create VerkleTree");
    println!("Created VerkleTree with depth 130, branching factor 256");

    // Inserting values
    let wallet_address = "fc91428771e2b031cd46b0478ce20a7af0b110d4";
    let key_wallet = hex::decode(wallet_address).expect("Failed to decode hex string");
    tree.insert(key_wallet.clone(), vec![13, 14, 15]);
    println!("Inserted wallet address \"{}\" with value {:?}", wallet_address, vec![13, 14, 15]);

    let wallet_address2 = "9dcd";
    let key_wallet2 = hex::decode(wallet_address2).expect("Failed to decode hex string");
    tree.insert(key_wallet2.clone(), vec![14, 15, 16]);
    println!("Inserted wallet address \"{}\" with value {:?}", wallet_address2, vec![14, 15, 16]);

    // Check if the keys are in the tree
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

    // Setting and checking commitments
    if let Err(e) = tree.set_commitments() {
        eprintln!("Error setting commitments: {:?}", e);
    } else {
        println!("Commitments set successfully.");
    }

    // Check all commitments in the tree
    match tree.check_commitments() {
        Ok(valid) => println!("All commitments in the tree are valid: {}", valid),
        Err(e) => eprintln!("Error checking commitments: {:?}", e),
    }

    // Test the verification for specific keys and generate proofs
    let keys_to_verify = vec![key_wallet.clone(), key_wallet2.clone()];
    for key in keys_to_verify {
        // Verify the path for the key
        match tree.verify_path(key.clone()) {
            Ok(valid) => println!("Verification for key {:?}: {}", hex::encode(&key), valid),
            Err(e) => eprintln!("Error verifying path for key {:?}: {:?}", hex::encode(&key), e),
        }

        // Generate and display the proof for the key
        if let Some(proof) = tree.generate_proof_for_key(&key) {
            println!("Proof for key {:?}: {:?}", hex::encode(&key), proof);
        } else {
            println!("No proof generated for key {:?}", hex::encode(&key));
        }
    }

    // Test the proof of membership for the key "fc91428771e2b031cd46b0478ce20a7af0b110d4"
    let key_to_search = "fc91428771e2b031cd46b0478ce20a7af0b110d4";
    let decoded_key_to_search = hex::decode(key_to_search).expect("Failed to decode hex string");
    let proof = tree.proof_of_membership_for_key(&decoded_key_to_search);

    match proof {
        Some(verkle_proof) => {
            println!("Proof of membership for key {}: {:?}", key_to_search, verkle_proof);
        },
        None => {
            println!("No proof of membership generated for key {}", key_to_search);
        },
    }

    // Test checking commitments for specific keys, including a non-existent key
    let non_existent_key = "9cd99c";
    let keys_to_check_commitment = vec![key_wallet.clone(), key_wallet2.clone(), hex::decode(non_existent_key).expect("Failed to decode hex string")];
    
    for key in keys_to_check_commitment {
        match tree.check_commitment_for_key(&key) {
            Ok(valid) => println!("Commitment valid for key {:?}: {}", hex::encode(&key), valid),
            Err(e) => eprintln!("Error checking commitment for key {:?}: {:?}", hex::encode(&key), e),
        }
    }
}

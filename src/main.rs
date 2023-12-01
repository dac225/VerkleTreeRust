use ark_ec::PairingEngine;
use ark_poly::UVPolynomial;
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::marlin::marlin_pc::MarlinKZG10;
use ark_poly_commit::PolynomialCommitment;
use ark_bls12_381::Bls12_381;
use rand::Rng;
use sha2::{Sha256, Digest};
use hex;
use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::env;
use std::path::PathBuf;

use VerkleTreeRust::VerkleTree;

/// Helper function to read data from file
pub fn read_data_from_file(file_path: PathBuf) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Box<dyn Error>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut data: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    
    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 2 {
            let address = parts[0].to_string().chars().map(|c| c as u8).collect();
            let balance = parts[1].to_string().chars().map(|c| c as u8).collect();
            data.push((address, balance));
        } else {
            eprintln!("Invalid line format: {}", line);
        }
    }

    Ok(data)
}

fn main() {
    let mut rng = rand::thread_rng();
    let degree = 256;

    type Fr = <Bls12_381 as PairingEngine>::Fr;
    type Poly = DensePolynomial<Fr>;
    type KZG10 = MarlinKZG10<Bls12_381, Poly>;

    let params = KZG10::setup(degree, None, &mut rng).unwrap();
    let (committer_key, verifier_key) = KZG10::trim(&params, degree, 0, None).unwrap();

    let depth = 32;
    let branching_factor = 256;

    // Create a VerkleTree with committer_key and verifier_key
    let mut tree = VerkleTree::new(depth, branching_factor)
        .expect("Failed to create VerkleTree");
    println!("Created VerkleTree with depth 130, branching factor 256");

    // use data_reader.rs to read data from files in the input_file folder
    let current_dir = env::current_dir().unwrap();
    let input_file_path = current_dir.join("input_files/test_data.txt");
    let data = read_data_from_file(input_file_path).expect("Failed to read data from file");

    // insert data into the tree
    for (key, value) in data {
        tree.insert(hex::decode(key.clone()).expect("Failed to decode hex string"), value.clone());
        println!("Inserted wallet address \"{:?}\" with value {:?}", key.clone(), value.clone());
    }

    // Setting and checking commitments
    if let Err(e) = tree.set_commitments() {
        eprintln!("Error setting commitments: {:?}", e);
    } else {
        println!("Commitments set successfully.");
    }

    // ask the user if they would like to enter a key for verification for membership
    let mut input = String::new();
    println!("Enter a key to verify for membership in the tree: ");
    std::io::stdin().read_line(&mut input).expect("Failed to read line");
    let user_search_key = hex::decode(input.trim()).expect("Failed to decode hex string");

    // In creating and proving a verkle tree proof, the proof would typically consist of  
        // 1) The combined_commitment of the tree (root commitmet)
        // 2) The path to the desired key (in verkle tree node indices)
        // 3) The sibling_commitments along the path to the desired key (all other commitments in the tree)
    // In our code, we provide the path to the desired key as the commitments that must be checked for membership because the 
        // re-assembling of the path commitments using the path indices and sibling commitments would necessitate implementing a 
        // new proof protocol which was time-infeasable.

    // Check all commitments in the tree 
    // This serves as the proof of correctness for the root and sibling commitments
    // If the user's chosen search-key is a member, this will also technically prove that the key is a member,
        // but we will also prove the membership of the key in the tree using the path_commitments to the key
    match tree.check_commitments() {
        Ok(valid) => println!("All commitments in the tree are valid: {}", valid),
        Err(e) => eprintln!("Error checking commitments: {:?}", e),
    }

    // Verify the path for the key
    match tree.verify_path(user_search_key.clone()) {
        Ok(valid) => println!("Verification for key {:?}: {}", hex::encode(&user_search_key), valid),
        Err(e) => eprintln!("Error verifying path for key {:?}: {:?}", hex::encode(&user_search_key), e),
    }

    // Generate and display the verkle proof of membership for the user's search key
    if let Some(proof) = tree.generate_proof_for_key(&user_search_key) {
        println!("Proof for key {:?}: {:?}", hex::encode(&user_search_key), proof);
    } else {
        println!("No proof generated for key {:?}", hex::encode(&user_search_key));
    }

    match tree.check_commitment_for_key(&user_search_key) {
        Ok(valid) => println!("Commitment valid for key {:?}: {}", hex::encode(&user_search_key), valid),
        Err(e) => eprintln!("Error checking commitment for key {:?}: {:?}", hex::encode(&user_search_key), e),
    }

}

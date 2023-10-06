use ark_poly_commit::marlin::marlin_pc::MarlinKZG10;
use ark_poly_commit::PolynomialCommitment;
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_bls12_381::Bls12_381;
use ark_ff::Field;
use rand::Rng;
use VerkleTreeRust::VerkleTree;

fn main() {
    type F = <Bls12_381 as ark_ec::PairingEngine>::Fr;
    type P = DensePolynomial<F>;
    type PC = MarlinKZG10<Bls12_381, P>;

    let mut rng = rand::thread_rng();
    let degree = 256;
    let params = PC::setup(degree, None, &mut rng).unwrap();
    let committer_key = PC::trim(&params, degree, 0, None).unwrap().0; 

    // Create the VerkleTree with the committer key, depth, and branching factor
    let depth = 16; // Adjust as needed
    let branching_factor = 256; // Adjust as needed

    // Create the VerkleTree
    let mut tree: VerkleTree<F, P, PC> = VerkleTree::new(committer_key.clone(), depth, branching_factor)
    .expect("Failed to create VerkleTree");
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

    let retrieved_value2 = tree.get(key_wallet);
    match retrieved_value2 {
        Some(value) => println!("Retrieved value for wallet address {}: {:?}", wallet_address, value),
        None => println!("No value found for wallet address {}", wallet_address),
    }
    
    // Retrieve the value associated with the wallet address
    let retrieved_value = tree.get(key_wallet2);
    match retrieved_value {
        Some(value) => println!("Retrieved value for wallet address {}: {:?}", wallet_address2, value),
        None => println!("No value found for wallet address {}", wallet_address2),
    }

}





use VerkleTreeRust::VerkleTree;

fn main() {
    let mut rng = rand::thread_rng();

    // Step 1: Initialization
    let mut tree = VerkleTree::new(None);
    let key1 = b"key1".to_vec();
    let value1 = b"value1".to_vec();
    let key2 = b"key2".to_vec();
    let value2 = b"value2".to_vec();

    // Step 2: Insertion
    tree.insert(key1.clone(), value1.clone());
    tree.insert(key2.clone(), value2.clone());

    // Step 3: Commit
    let commit1 = tree.compute_commitment();
    println!("Commitment after inserting key1 and key2: {:?}", commit1);

    // Step 4: Generate proofs
    let proof_for_key1 = tree.root.proof_generation(key1.clone(), &tree.params.1).expect("Proof generation for key1 failed");
    let proof_for_key2 = tree.root.proof_generation(key2.clone(), &tree.params.1).expect("Proof generation for key2 failed");
    
    // Assuming proof_generation returns a Vec and the actual proof is the first element
    let actual_proof_for_key1 = &proof_for_key1;
    let actual_proof_for_key2 = &proof_for_key2;
    println!("Proof for key1: {:?}", proof_for_key1);
    println!("Proof for key2: {:?}", proof_for_key2);
    

    // Step 5: Verify proofs
    let is_verified_key1 = tree.verify(&commit1, key1.clone(), value1.clone(), actual_proof_for_key1);
    assert!(is_verified_key1, "Verification for key1 failed");

    let is_verified_key2 = tree.verify(&commit1, key2.clone(), value2.clone(), actual_proof_for_key2);
    assert!(is_verified_key2, "Verification for key2 failed");

    // For additional testing: modify the tree and compute a new commitment
    let key3 = b"key3".to_vec();
    let value3 = b"value3".to_vec();
    tree.insert(key3.clone(), value3.clone());
    let commit2 = tree.compute_commitment();
    println!("Commitment after inserting key3: {:?}", commit2);

    assert_ne!(commit1, commit2, "The commitments should not be the same after modifying the tree");

    println!("All tests passed!");
}

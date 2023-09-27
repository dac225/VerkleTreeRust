use VerkleTreeRust::{hash, Node, VerkleTree};

fn main() {
    // Step 1: Insertion
    let mut tree = VerkleTree::new(None);
    tree.insert(b"key1".to_vec(), b"value1".to_vec());
    tree.insert(b"key2".to_vec(), b"value2".to_vec());

    // Step 2: Commit
    let commit1 = tree.commitment();
    println!("Commitment after inserting key1 and key2: {:?}", commit1);

    // Now, modify the tree and get a new commitment
    tree.insert(b"key3".to_vec(), b"value3".to_vec());
    let commit2 = tree.commitment();
    println!("Commitment after inserting key3: {:?}", commit2);

    // Ensure that the commitments are different
    assert_ne!(commit1, commit2, "The commitments should not be the same after modifying the tree");

    println!("Tests passed!");
}

// Note: Depending on how your library is set up, you might need to use different 
// methods or dereference types to make the above code compile.

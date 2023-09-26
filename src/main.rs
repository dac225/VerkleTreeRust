use VerkleTreeRust::{hash, Node, VerkleTree};

fn main() {
    let mut tree = VerkleTree::new(None);

    // Insert 257 unique prefixes to test max width
    for i in 0..=256 {
        let key = vec![i as u8];
        let value = b"value".to_vec();
        tree.insert(key, value);
    }

    let data = b"Hello, world!";
    let hashed_data = hash(data);
    println!("Hashed data: {:?}", hashed_data);

    // Create a VerkleTree instance with a blank root
    let mut tree_with_blank_root = VerkleTree::new(None);
    println!("Created a new VerkleTree with a blank root key: {:?}", truncate_hash(&tree_with_blank_root.root.key));

    // Test inserting a key-value pair
    tree_with_blank_root.insert(b"Hello".to_vec(), b"World".to_vec());
    println!("After inserting key1-value1 into tree_with_blank_root:");
    print_tree(&tree_with_blank_root.root, 0);

    // Create a VerkleTree instance with the hashed data as root key
    let mut tree_with_key = VerkleTree::new(Some(hashed_data.clone()));
    println!("\nCreated a new VerkleTree with root key: {:?}", truncate_hash(&tree_with_key.root.key));

    // Test inserting a couple of key-value pairs
    tree_with_key.insert(b"some_different_key".to_vec(), b"value_for_hashed_data".to_vec());
    tree_with_key.insert(b"another_key".to_vec(), b"another_value".to_vec());
    println!("After inserting data into tree_with_key:");
    print_tree(&tree_with_key.root, 0);
}

// Recursive function to print the tree
fn print_tree(node: &Node, level: usize) {
    let padding: String = (0..level).map(|_| "  ").collect();
    println!("{}Key: {:?}, Value: {:?}", padding, truncate_hash(&node.key), node.value);
    
    for child in &node.children {
        print_tree(child, level + 1);
    }
}

// Utility function to truncate hashes for display
fn truncate_hash(hash: &[u8]) -> Vec<u8> {
    hash.iter().cloned().take(4).collect()  // Taking only the first 4 bytes for display
}

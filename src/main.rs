use VerkleTreeRust::{hash, Node, VerkleTree};

fn main() {
    let data = b"Hello, world!";
    let hashed_data = hash(data);
    println!("Hashed data: {:?}", hashed_data);

    // Create a VerkleTree instance with a blank root
    let tree_with_blank_root = VerkleTree::new(None);
    println!("Created a new VerkleTree with a blank root key: {:?}", tree_with_blank_root.root.key);

    // Create a VerkleTree instance with the hashed data as root key
    let tree_with_key = VerkleTree::new(Some(hashed_data));
    println!("Created a new VerkleTree with root key: {:?}", tree_with_key.root.key);

    // TODO: Extend this to add more nodes to the tree and test further functionality
}

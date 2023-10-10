use ark_ec::models::{short_weierstrass_jacobian::GroupAffine as SWAffine, SWModelParameters};
use ark_ec::PairingEngine;
use ark_ff::{Field, PrimeField};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::marlin::marlin_pc::MarlinKZG10;
use ark_poly_commit::{Polynomial, PolynomialCommitment, PolynomialLabel};
use sha2::{Sha256, Digest}; // Explicitly import the Digest trait
use rand::RngCore;
use ark_bls12_381::Bls12_381;

// TODOs:
    // Create functionality to move data from test_data.txt into a trie
    // reimplement test cases to account for data coming in from another file
    // explore the commitment and verification process 
        // everything we need to extract from the trie/nodes
        // everything we need to produce to open/prove a polynomial

// Set up for Polynomial Commitments using ark library
type BlsFr = <Bls12_381 as PairingEngine>::Fr;
type Poly = DensePolynomial<BlsFr>;

type KZG10 = MarlinKZG10<Bls12_381, Poly>;

pub fn setup<R: RngCore>(
    max_degree: usize,
    _num_vars: Option<usize>,
    rng: &mut R
) -> Result<
    (
        <KZG10 as PolynomialCommitment<BlsFr, Poly>>::UniversalParams,
        <KZG10 as PolynomialCommitment<BlsFr, Poly>>::CommitterKey,
        <KZG10 as PolynomialCommitment<BlsFr, Poly>>::VerifierKey,
    ),
    <KZG10 as PolynomialCommitment<BlsFr, Poly>>::Error
> {
    let params = KZG10::setup(max_degree, _num_vars, rng)?;
    let (committer_key, verifier_key) = KZG10::trim(&params, max_degree, 0, None)?;
    Ok((params, committer_key, verifier_key))
}

// hash function (SHA-256 most likely)
pub fn hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// LeafNode Structure
#[derive(Clone)]
pub struct LeafNode {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

// Node structure
pub struct Node<F, P, PC>
where
    F: Field,
    P: Polynomial<F>,
    PC: PolynomialCommitment<F, P>,
{
    pub key: Vec<u8>,
    pub children: Vec<Entry<F, P, PC>>,
    pub commitment: Option<<PC as PolynomialCommitment<F, P>>::Commitment>,
    pub max_children: usize,
    pub depth: usize,
}

pub enum Entry<F, P, PC>
where
    F: Field,
    P: Polynomial<F>,
    PC: PolynomialCommitment<F, P>,
{
    InternalNode(Node<F, P, PC>),
    Leaf(LeafNode),
}

impl<F, P, PC> Node<F, P, PC>
where
    F: Field,
    P: Polynomial<F>,
    PC: PolynomialCommitment<F, P>,
{
    pub fn new(key: Vec<u8>, max_children: usize, depth: usize) -> Self {
        Node {
            // key: hash(&key),
            key,
            children: Vec::new(),
            commitment: None,
            max_children,
            depth,
        }
    }

    pub fn print_tree(&self) {
        self.print_node(0); // Start the traversal from depth 0
    }

    fn print_node(&self, depth: usize) {
        let indent = "  ".repeat(depth); // Add indentation for better visualization

        match self.children.iter().next() {
            Some(Entry::InternalNode(_)) => {
                // This node is an internal node
                println!("{}Internal Node at depth: {}, Key: {:?}", indent, depth, self.key);
                for child in &self.children {
                    if let Entry::InternalNode(node) = child {
                        node.print_node(depth + 1); // Recursively print child nodes
                    }
                }
            }
            Some(Entry::Leaf(leaf)) => {
                // This node is a leaf node
                println!("{}Leaf Node at depth: {}, Key: {:?}, Value: {:?}", indent, depth, self.key, leaf.value);
            }
            None => {
                // This node has no children (should not happen in a valid tree)
                println!("{}Empty Node at depth: {}, Key: {:?}", indent, depth, self.key);
            }
        }
    }

    pub fn get(&self, key: Vec<u8>) -> Option<Vec<u8>> {
        let mut current_node = self;
        let mut depth = 0;
    
        // Continue while there's a node at the current depth to traverse
        while let Some(index) = current_node.children.iter().position(|child| {
            match child {
                Entry::InternalNode(node) => {
                    // Check if the first key byte of the internal node matches the current key byte
                    node.key[0] == key[depth]
                },
                Entry::Leaf(leaf) => {
                    // Check if the leaf node's key matches the target key
                    leaf.key == key
                }
            }
        }) {
            match &current_node.children[index] {
                Entry::InternalNode(node) => {
                    println!("Traversing to Internal Node at depth: {}, Key: {:?}", node.depth, node.key);
                    current_node = node;
                    depth += 1;
                },
                Entry::Leaf(leaf) => {
                    println!("Found Leaf Node at depth: {}, Key: {:?}", depth, leaf.key);
                    if leaf.key == key {
                        return Some(leaf.value.clone()); // Return the value if the leaf node matches the target key
                    } else {
                        println!("Key mismatch at depth: {}, Expected: {:?}, Actual: {:?}", depth, key, leaf.key);
                        return None; // Return None if the leaf node key doesn't match the target key
                    }
                }
            }
        }
    
        // Print a message and return None if traversal stopped without finding a matching leaf node
        println!("Traversal stopped at depth: {:?}, Key: {:?}", depth, key);
        None
    }
    
    
      
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>, max_depth: usize) {
        // Print debug messages for the insertion process
        println!("Inserting key of length: {}", key.len());
        println!("Current key: {:?}", key);
    
        // Start at the root node
        let mut current_node = self;
    
        // Iterate through the depths of the tree
        for depth in 0..max_depth {
            // If we've reached the end of the key, insert a new leaf node
            if depth == key.len() {
                // Create a new leaf node with the provided key and value
                let new_leaf = Entry::Leaf(LeafNode { key: key.clone(), value: value.clone() });
                println!("Created a new LeafNode for key: {:?} at depth: {}", key, depth);
                println!("LeafNode value: {:?}", value);
    
                // Add the new leaf node to the current node's children
                current_node.children.push(new_leaf);
    
                // Check if a leaf node was successfully inserted
                if let Some(_index) = current_node.children.iter().position(|child| matches!(child, Entry::Leaf(_))) {
                    println!("Leaf node verified at depth: {}, Key: {:?}", depth, key);
                }
                else {
                    println!("Leaf node cannot be verified at depth: {}, Key: {:?}", depth, key)
                }
                return; // Insertion is complete
            }
    
            // Get the prefix at the current depth
            let prefix = key[depth];
    
            // Find the position of the child node that matches the prefix
            let position = current_node.children.iter().position(|child| match child {
                Entry::InternalNode(node) => node.key[0] == prefix,
                Entry::Leaf(leaf) => leaf.key[depth] == prefix,
            });
            
            // matching for a child at a specific position
            match position {
                Some(index) => {
                    // Remove the existing child node from the current node
                    let child = current_node.children.remove(index);
    
                    match child {
                        Entry::InternalNode(node) => {
                            // Reinsert an internal node that matches the prefix
                            println!("Reinserting an Internal Node at depth: {}", node.depth);
                            println!("Node key: {:?}", node.key);
                            current_node.children.insert(index, Entry::InternalNode(node));
    
                            // Set the current node to the internal node for further traversal
                            current_node = match current_node.children.get_mut(index).unwrap() {
                                Entry::InternalNode(node) => node,
                                _ => panic!("Expected an InternalNode!"),
                            };
                        },
                        Entry::Leaf(leaf) => {
                            if leaf.key == key {
                                // Update the value for an existing leaf node with the same key
                                println!("Updating value for an existing LeafNode with key: {:?}", key);
                                current_node.children.insert(index, Entry::Leaf(LeafNode { key: key.clone(), value: value.clone() }));
                            } else {
                                // Create a new internal node and insert both the existing leaf and a new leaf
                                let mut new_internal_node = Node::new(vec![prefix], current_node.max_children, depth + 1);
                                println!("Created Internal Node at depth: {}", new_internal_node.depth);
                                println!("Node key: {:?}", new_internal_node.key);
    
                                new_internal_node.children.push(Entry::Leaf(leaf));
                                new_internal_node.children.push(Entry::Leaf(LeafNode { key: key.clone(), value: value.clone() }));
                                println!("Created a new LeafNode for key: {:?} at depth: {}", key, depth);
                                println!("LeafNode value: {:?}", value);
    
                                // Insert the new internal node into the current node's children
                                current_node.children.insert(index, Entry::InternalNode(new_internal_node));
                            }
                            return; // Insertion is complete
                        }
                    }
                },
                None => {
                    // Create a new internal node for the prefix and insert it into the current node's children
                    let new_node = Node::new(vec![prefix], current_node.max_children, depth + 1);
                    println!("Created Internal Node at depth: {}", new_node.depth);
                    println!("Node key: {:?}", new_node.key);
                    current_node.children.push(Entry::InternalNode(new_node));
    
                    // Set the current node to the newly created internal node for further traversal
                    current_node = match current_node.children.last_mut().unwrap() {
                        Entry::InternalNode(node) => node,
                        _ => panic!("Expected an InternalNode!"),
                    };
                }
            }
        }
    }    
    
}

pub struct VerkleTree<F, P, PC>
where
    F: Field,
    P: Polynomial<F>,
    PC: PolynomialCommitment<F, P>,
{
    pub root: Node<F, P, PC>,
    pub params: (
        <KZG10 as PolynomialCommitment<BlsFr, Poly>>::UniversalParams,
        <KZG10 as PolynomialCommitment<BlsFr, Poly>>::CommitterKey,
        <KZG10 as PolynomialCommitment<BlsFr, Poly>>::VerifierKey,
    ),
    pub max_depth: usize,
}

impl<F, P, PC> VerkleTree<F, P, PC>
where
    F: Field,
    P: Polynomial<F>,
    PC: PolynomialCommitment<F, P>,
{
    pub fn new(
        comm_key: PC::CommitterKey,
        depth: usize,
        branching_factor: usize,
    ) -> Result<Self, <KZG10 as PolynomialCommitment<BlsFr, Poly>>::Error> {
        let params = setup(branching_factor, None, &mut rand::thread_rng())?;
        Ok(VerkleTree {
            root: Node::new(vec![], branching_factor, 0), // Initialize depth to 0
            params,
            max_depth: depth,
        })
    }
    
    pub fn print_tree(&self) {
        self.root.print_tree();
    }
    
    pub fn get(&self, key: Vec<u8>) -> Option<Vec<u8>> {
        self.root.get(key)
    }

    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.root.insert(key, value, self.max_depth);

    }

}



#[cfg(test)]
mod tests {
    use super::*;
    use ark_poly_commit::marlin::marlin_pc::MarlinKZG10;
    use ark_poly_commit::PolynomialCommitment;
    use ark_poly::polynomial::univariate::DensePolynomial;
    use ark_bls12_381::Bls12_381;
    use ark_ff::Field;
    use rand::Rng;

    fn setup_tree() -> VerkleTree<<Bls12_381 as ark_ec::PairingEngine>::Fr, DensePolynomial<<Bls12_381 as ark_ec::PairingEngine>::Fr>, MarlinKZG10<Bls12_381, DensePolynomial<<Bls12_381 as ark_ec::PairingEngine>::Fr>>> {
        let mut rng = rand::thread_rng();
        let degree = 256;
        let params = MarlinKZG10::<Bls12_381, DensePolynomial<<Bls12_381 as ark_ec::PairingEngine>::Fr>>::setup(degree, None, &mut rng).unwrap();
        // I need clarification on the syntax of ln 326. More specifically, the .0 at the end of the declaration. -vic
        let committer_key = MarlinKZG10::<Bls12_381, DensePolynomial<<Bls12_381 as ark_ec::PairingEngine>::Fr>>::trim(&params, degree, 0, None).unwrap().0;

        let depth = 16;
        let branching_factor = 256;

        VerkleTree::new(committer_key, depth, branching_factor).expect("Failed to create VerkleTree")
    }

    #[test]
    fn test_insert_and_get_single_value() {
        let mut tree = setup_tree();
    
        let key = hex::decode("4cc4").expect("Failed to decode hex string");
        let value = vec![13, 14, 15];
    
        tree.insert(key.clone(), value.clone());
    
        let retrieved_value = tree.get(key.clone());
        assert_eq!(retrieved_value, Some(value));
    }
    
    #[test]
    fn test_insert_and_get_multiple_keys() {
        let mut tree = setup_tree();

        let key1 = hex::decode("4cc4").expect("Failed to decode hex string");
        let value1 = vec![13, 14, 15];

        let key2 = hex::decode("9cd9").expect("Failed to decode hex string");
        let value2 = vec![1, 2, 3, 4];

        tree.insert(key1.clone(), value1.clone());
        tree.insert(key2.clone(), value2.clone());

        let retrieved_value1 = tree.get(key1.clone());
        let retrieved_value2 = tree.get(key2.clone());

        assert_eq!(retrieved_value1, Some(value1));
        assert_eq!(retrieved_value2, Some(value2));
    }

    #[test]
    fn test_insert_and_get_keys_with_collisions() {
        let mut tree = setup_tree();

        let key1 = hex::decode("4cc4").expect("Failed to decode hex string");
        let value1 = vec![13, 14, 15];

        let key2 = hex::decode("4cc5").expect("Failed to decode hex string");
        let value2 = vec![1, 2, 3, 4];

        tree.insert(key1.clone(), value1.clone());
        tree.insert(key2.clone(), value2.clone());

        let retrieved_value1 = tree.get(key1.clone());
        let retrieved_value2 = tree.get(key2.clone());

        assert_eq!(retrieved_value1, Some(value1));
        assert_eq!(retrieved_value2, Some(value2));
    }

    #[test]
    fn test_insert_and_get_empty_values() {
        let mut tree = setup_tree();

        let key1 = hex::decode("4cc4").expect("Failed to decode hex string");
        let value1: Vec<u8> = vec![]; // Empty value

        tree.insert(key1.clone(), value1.clone());

        let retrieved_value1 = tree.get(key1.clone());

        assert_eq!(retrieved_value1, Some(value1));
    }

    #[test]
    fn test_insert_and_get_nonexistent_key() {
        let mut tree = setup_tree();
    
        let key1 = hex::decode("4cc4").expect("Failed to decode hex string");
        let value1 = vec![13, 14, 15];
    
        tree.insert(key1.clone(), value1.clone());
    
        let key2 = hex::decode("9dc4").expect("Failed to decode hex string");
        let retrieved_value2 = tree.get(key2.clone());
    
        assert_eq!(retrieved_value2, None);
    }
    

}

use std::fmt;
use ark_ec::PairingEngine;
use ark_ff::{Field, PrimeField};
use ark_poly::UVPolynomial;
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::marlin::marlin_pc::MarlinKZG10;
use ark_poly_commit::{Polynomial, PolynomialCommitment, PolynomialLabel};
use sha2::{Sha256, Digest}; // Explicitly import the Digest trait
use rand::RngCore;
use ark_bls12_381::Bls12_381;

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

pub fn hash_to_field<F>(hashed_data: &[u8]) -> F 
where
    F: PrimeField, // Add this trait bound
{
    F::from_le_bytes_mod_order(hashed_data)
}


// LeafNode Structure
#[derive(Clone)]
pub struct LeafNode {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

// Node structure
pub struct Node {
    pub key: Vec<u8>,
    pub children: Vec<Entry>, // Entry now uses BlsFr implicitly
    pub commitment: Option<<KZG10 as PolynomialCommitment<BlsFr, Poly>>::Commitment>,
    pub max_children: usize,
    pub depth: usize,
}


pub enum Entry {
    InternalNode(Node),
    Leaf(LeafNode),
}

#[derive(Debug)] 
pub struct VerkleProof {
    pub path: Vec<VerkleNodeProof>,
}

#[derive(Debug)] 
pub struct VerkleNodeProof {
    pub key: Vec<u8>,
    pub commitment: Option<<KZG10 as PolynomialCommitment<BlsFr, Poly>>::Commitment>,
}

impl Node {
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
        // Hash the key first
        let hashed_key = hash(&key);
    
        let mut current_node = self;
        let mut depth = 0;
    
        // Continue while there's a node at the current depth to traverse
        while let Some(index) = current_node.children.iter().position(|child| {
            match child {
                Entry::InternalNode(node) => {
                    // Check if the first byte of the internal node's key matches the current byte of the hashed key
                    node.key.get(0) == hashed_key.get(depth)
                },
                Entry::Leaf(leaf) => {
                    // Check if the leaf node's key matches the hashed key
                    leaf.key == hashed_key
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
                    if leaf.key == hashed_key {
                        return Some(leaf.value.clone()); // Return the value if the leaf node matches the hashed key
                    } else {
                        println!("Key mismatch at depth: {}, Expected: {:?}, Actual: {:?}", depth, hashed_key, leaf.key);
                        return None; // Return None if the leaf node key doesn't match the hashed key
                    }
                }
            }
        }
    
        // Print a message and return None if traversal stopped without finding a matching leaf node
        println!("Traversal stopped at depth: {:?}, Key: {:?}", depth, hashed_key);
        None
    }
    
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>, max_depth: usize) {
        // Hash the entire key first
        let hashed_key = hash(&key);
    
        // Print debug messages for the insertion process
        println!("Inserting key of length: {}", hashed_key.len());
        println!("Current hashed key: {:?}", hashed_key);
    
        // Start at the root node
        let mut current_node = self;
    
        // Iterate through the depths of the tree
        for depth in 0..max_depth {
            // If we've reached the end of the hashed key, insert a new leaf node
            if depth == hashed_key.len() {
                let new_leaf = Entry::Leaf(LeafNode { key: hashed_key.clone(), value: value.clone() });
                println!("Created a new LeafNode for hashed key: {:?} at depth: {}", hashed_key, depth);
                println!("LeafNode value: {:?}", value);
    
                current_node.children.push(new_leaf);
                return; // Insertion is complete
            }
    
            // Get the prefix at the current depth from the hashed key
            let prefix = hashed_key[depth];
    
            // Find the position of the child node that matches the prefix
            let position = current_node.children.iter().position(|child| match child {
                Entry::InternalNode(node) => node.key.get(0) == Some(&prefix),
                Entry::Leaf(leaf) => leaf.key.get(depth) == Some(&prefix),
            });
    
            // Handle the matching child node
            match position {
                Some(index) => {
                    // Existing logic for handling the found node
                    let child = current_node.children.remove(index);
    
                    match child {
                        Entry::InternalNode(node) => {
                            println!("Reinserting an Internal Node at depth: {}", node.depth);
                            println!("Node key: {:?}", node.key);
                            current_node.children.insert(index, Entry::InternalNode(node));
    
                            current_node = match current_node.children.get_mut(index).unwrap() {
                                Entry::InternalNode(node) => node,
                                _ => panic!("Expected an InternalNode!"),
                            };
                        },
                        Entry::Leaf(leaf) => {
                            if leaf.key == hashed_key {
                                println!("Updating value for an existing LeafNode with key: {:?}", hashed_key);
                                current_node.children.insert(index, Entry::Leaf(LeafNode { key: hashed_key.clone(), value: value.clone() }));
                            } else {
                                let mut new_internal_node = Node::new(vec![prefix], current_node.max_children, depth + 1);
                                println!("Created Internal Node at depth: {}", new_internal_node.depth);
                                println!("Node key: {:?}", new_internal_node.key);
    
                                new_internal_node.children.push(Entry::Leaf(leaf));
                                new_internal_node.children.push(Entry::Leaf(LeafNode { key: hashed_key.clone(), value: value.clone() }));
                                println!("Created a new LeafNode for key: {:?} at depth: {}", hashed_key, depth);
                                println!("LeafNode value: {:?}", value);
    
                                current_node.children.insert(index, Entry::InternalNode(new_internal_node));
                            }
                            return; // Insertion is complete
                        }
                    }
                },
                None => {
                    let new_node = Node::new(vec![prefix], current_node.max_children, depth + 1);
                    println!("Created Internal Node at depth: {}", new_node.depth);
                    println!("Node key: {:?}", new_node.key);
                    current_node.children.push(Entry::InternalNode(new_node));
    
                    current_node = match current_node.children.last_mut().unwrap() {
                        Entry::InternalNode(node) => node,
                        _ => panic!("Expected an InternalNode!"),
                    };
                }
            }
        }
    }
    
    /// Recursively sets the commitments for this node and its children.
    pub fn set_commitments_recursive(
        &mut self, 
        ck: &<KZG10 as PolynomialCommitment<BlsFr, Poly>>::CommitterKey,
        rng: &mut impl RngCore,
    ) -> Result<(), <KZG10 as PolynomialCommitment<BlsFr, Poly>>::Error> {
        let mut coefficients = Vec::new();

        // For each child, hash its key and convert it into a field element
        for child in &self.children {
            let child_key = match child {
                Entry::InternalNode(node) => &node.key,
                Entry::Leaf(leaf) => &leaf.key,
            };
            let child_hash = hash(child_key);
            let field_element = hash_to_field::<BlsFr>(&child_hash);
            coefficients.push(field_element);
        }

        // Create a DensePolynomial from coefficients
        let polynomial = DensePolynomial::from_coefficients_vec(coefficients);
        let labeled_polynomial = ark_poly_commit::LabeledPolynomial::new("poly".to_string(), polynomial, None, None);

        // Compute the commitment
        let commitment_result = KZG10::commit(ck, std::iter::once(&labeled_polynomial), Some(rng))?;
        let commitment = commitment_result.0.first().cloned().unwrap().commitment().clone();

        // Store the commitment
        self.commitment = Some(commitment);

        // Recursively set commitments for child nodes
        for child in &mut self.children {
            if let Entry::InternalNode(ref mut internal_node) = child {
                internal_node.set_commitments_recursive(ck, rng)?;
            }
        }

        Ok(())
    }

    pub fn print_commitments(&self, depth: usize) {
        let indent = "  ".repeat(depth);
        println!("{}Node at depth {}: {:?}", indent, depth, self.commitment);

        for child in &self.children {
            match child {
                Entry::InternalNode(node) => {
                    node.print_commitments(depth + 1);
                },
                Entry::Leaf(leaf) => {
                    println!("{}Leaf at depth {}: {:?}", indent, depth + 1, leaf.key);
                },
            }
        }
    }

    /// Checks the commitment of the node.
    fn check_commitment(
        &self, 
        ck: &<KZG10 as PolynomialCommitment<BlsFr, Poly>>::CommitterKey
    ) -> bool {
        // Step 1: Recompute the polynomial from the node's data
        let mut coefficients = Vec::new();
        for child in &self.children {
            let child_key = match child {
                Entry::InternalNode(node) => &node.key,
                Entry::Leaf(leaf) => &leaf.key,
            };
            let child_hash = hash(child_key);
            let field_element = hash_to_field::<BlsFr>(&child_hash);
            coefficients.push(field_element);
        }
        let polynomial = DensePolynomial::from_coefficients_vec(coefficients);

        // Step 2: Recompute the commitment
        let labeled_polynomial = ark_poly_commit::LabeledPolynomial::new("poly".to_string(), polynomial, None, None);
        let recomputed_commitment = match KZG10::commit(ck, std::iter::once(&labeled_polynomial), None) {
            Ok(commitment) => commitment.0.first().cloned().unwrap().commitment().clone(),
            Err(_) => return false,
        };

        // Step 3: Compare the recomputed commitment with the stored one
        match &self.commitment {
            Some(stored_commitment) => *stored_commitment == recomputed_commitment,
            None => false,
        }
    }

    pub fn get_path(&self, key: &[u8]) -> Vec<&Node> {
        let mut path = Vec::new();
        let mut current_node = self;

        loop {
            path.push(current_node);
            if current_node.is_leaf() && current_node.key == key {
                break;
            }

            // Determine the next node to move to
            let next_node = current_node.children.iter().find_map(|child| {
                match child {
                    Entry::InternalNode(node) => Some(node),
                    Entry::Leaf(leaf) if leaf.key == key => Some(current_node),
                    _ => None,
                }
            });

            match next_node {
                Some(node) => current_node = node,
                None => break, // Key not found, return the path so far
            }
        }

        path
    }

    // Helper method to check if a node is a leaf
    fn is_leaf(&self) -> bool {
        self.children.is_empty() // or any other condition you use to define a leaf
    }

    /// Generate a proof for the existence of a key in the Verkle tree.
    pub fn generate_proof(&self, key: &[u8]) -> Option<VerkleProof> {
        let mut current_node = self;
        let mut path: Vec<VerkleNodeProof> = Vec::new();
        let hashed_key = hash(key); // Hash the key if your tree uses hashed keys

        // Loop until a leaf is found or there are no more nodes to check
        while let Some(child) = current_node.children.iter().find(|&child| {
            match child {
                Entry::InternalNode(node) => {
                    println!("Matching Internal Node: {:?}", node.key);
                    node.key[0] == hashed_key[0]
                },
                Entry::Leaf(leaf) => {
                    println!("Matching Leaf Node: {:?}", leaf.key);
                    leaf.key == hashed_key
                },
                _ => false,
            }
        }) {
            // Construct node proof for the current node
            let node_proof = VerkleNodeProof {
                key: current_node.key.clone(),
                commitment: current_node.commitment.clone(),
                // Include other necessary data for the proof
            };
            path.push(node_proof);

            // Check if the current node is the target leaf node
            if let Entry::Leaf(leaf) = child {
                if leaf.key == hashed_key {
                    break; // Stop if the target leaf node is found
                }
            }

            // Move to the next node (only if it's an internal node)
            if let Entry::InternalNode(next_node) = child {
                current_node = next_node;
            } else {
                break; // Stop if it's a leaf but not the target
            }
        }

        // Return None if no leaf with the key is found
        if path.last().map_or(true, |p| !matches!(p, VerkleNodeProof { key: _, commitment: _ })) {
            return None;
        }

        Some(VerkleProof { path })
    }

    pub fn proof_of_membership(
        &self,
        key: &[u8],
    ) -> Option<VerkleProof> {
        // Retrieve the node at the level of the tree using the raw key
        let node = self.get(key.to_vec());
    
        // Generate the Verkle proof based on whether the key is found or not
        let proof = self.generate_proof(key);
    
        match node {
            Some(_) => println!("Key found, generating proof of membership."),
            None => println!("Key not found, generating proof of non-membership."),
        }
    
        proof
    }
    
    
}

pub struct VerkleTree {
    pub root: Node,
    pub params: (
        <KZG10 as PolynomialCommitment<BlsFr, Poly>>::UniversalParams,
        <KZG10 as PolynomialCommitment<BlsFr, Poly>>::CommitterKey,
        <KZG10 as PolynomialCommitment<BlsFr, Poly>>::VerifierKey,
    ),
    pub max_depth: usize,
}


impl VerkleTree {
    pub fn new(
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
    // Public method to set commitments on the tree
    pub fn set_commitments(&mut self) -> Result<(), <KZG10 as PolynomialCommitment<BlsFr, Poly>>::Error> {
        let committer_key = &self.params.1;
        let mut rng = rand::thread_rng();

        // Start the commitment setting process from the root node
        self.root.set_commitments_recursive(committer_key, &mut rng)
    }

    pub fn print_commitments(&self) {
        println!("Tree Commitments:");
        self.root.print_commitments(0);
    }

    /// Verifies the commitments of the entire tree.
    pub fn check_commitments(&self) -> bool {
        let ck = &self.params.1; // Committer key
        self.root.check_commitment(ck)
    }

    // Verify the commitment path for a specific key
    pub fn verify_path(&self, key: Vec<u8>) -> bool {
        let path = self.root.get_path(&key);
        for node in path {
            let ck = &self.params.1; // Committer key
            if !node.check_commitment(ck) {
                return false;
            }
        }
        true
    }

    /// Generate a proof for a given key within the Verkle tree.
    pub fn generate_proof_for_key(&self, key: &[u8]) -> Option<VerkleProof> {
        self.root.generate_proof(key)
    }
    
    pub fn proof_of_membership_for_key(
        &self,
        key: &[u8],
    ) -> Option<VerkleProof> {
        self.root.proof_of_membership(key)
    }

}



#[cfg(test)]
mod tests {
    use super::*;
    use ark_poly_commit::marlin::marlin_pc::MarlinKZG10;
    // use ark_poly_commit::PolynomialCommitment;
   // use ark_poly::polynomial::univariate::DensePolynomial;
    use ark_bls12_381::Bls12_381;
   // use ark_ff::Field;
    // use rand::Rng;
    
    fn setup_tree() -> VerkleTree {
        let mut rng = rand::thread_rng();
        let degree = 256;
    
        // Set up the parameters, committer key, and verifier key
        let (params, committer_key, verifier_key) = setup(degree, None, &mut rng).unwrap();
    
        let depth = 16;
        let branching_factor = 256;
    
        // Initialize the VerkleTree with the necessary parameters
        VerkleTree::new(depth, branching_factor).expect("Failed to create VerkleTree")
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

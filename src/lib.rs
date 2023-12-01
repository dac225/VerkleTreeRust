use ark_ec::PairingEngine;
use ark_ff::PrimeField;
use ark_poly::UVPolynomial;
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::marlin::marlin_pc::MarlinKZG10;
use ark_poly_commit::{PolynomialCommitment, LabeledCommitment};
use sha2::{Sha256, Digest}; 
use rand::RngCore;
use ark_bls12_381::Bls12_381;
use ark_ff::UniformRand;
use ark_poly_commit::PCRandomness;
use rand::thread_rng;

// Set up for Polynomial Commitments using ark library
type BlsFr = <Bls12_381 as PairingEngine>::Fr;
type Poly = DensePolynomial<BlsFr>;

type KZG10 = MarlinKZG10<Bls12_381, Poly>;

/// Wrapper for the setup function that returns the necessary parameters for the VerkleTree polynomial commitment scheme
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

/// sha256 hash function wrapper
pub fn hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Hashes the given data and converts it into a field element
pub fn hash_to_field<F>(hashed_data: &[u8]) -> F 
where
    F: PrimeField, // Add this trait bound
{
    F::from_le_bytes_mod_order(hashed_data)
}

/// LeafNode Structure
#[derive(Clone)]
pub struct LeafNode {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// Node structure
pub struct Node {
    pub key: Vec<u8>,
    pub children: Vec<Entry>, // Entry now uses BlsFr implicitly
    pub commitment: Option<<KZG10 as PolynomialCommitment<BlsFr, Poly>>::Commitment>,
    pub max_children: usize,
    pub depth: usize,
}

/// Node Entry structure
pub enum Entry {
    InternalNode(Node),
    Leaf(LeafNode),
}

/// PathProof structure
#[derive(Debug)] 
pub struct PathProof {
    pub path: Vec<VerkleNodeProof>,
}

/// VerkleNodeProof structure
#[derive(Debug)] 
pub struct VerkleNodeProof {
    pub key: Vec<u8>,
    pub commitment: Option<<KZG10 as PolynomialCommitment<BlsFr, Poly>>::Commitment>,
}

/// Node functions
impl Node {
    /// Create a new node with the given key, max_children, and depth
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

    /// Print the tree starting at depth 0
    pub fn print_tree(&self) {
        self.print_node(0); // Start the traversal from depth 0
    }

    /// Helper method to print a node
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

    /// Get the value for a given key
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
                    // println!("Traversing to Internal Node at depth: {}, Key: {:?}", node.depth, node.key);
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
    
    /// Get the path to a leaf node with the given key
    pub fn get_path(&self, key: &[u8]) -> Result<Vec<&Node>, <KZG10 as PolynomialCommitment<BlsFr, Poly>>::Error> {
        let hashed_key = hash(key);
        let mut current_node = self;
        let mut path: Vec<&Node> = Vec::new();
        let mut depth = 0;
    
        loop {
            path.push(current_node);
    
            if current_node.children.is_empty() {
                break; // Reached a leaf node or an empty node
            }
    
            // Find the next node to traverse based on the hashed key
            let index_option = current_node.children.iter().position(|child| {
                match child {
                    Entry::InternalNode(node) => {
                        node.key.get(0) == hashed_key.get(depth)
                    },
                    Entry::Leaf(leaf) => {
                        leaf.key == hashed_key
                    }
                }
            });
    
            match index_option {
                Some(index) => {
                    match &current_node.children[index] {
                        Entry::InternalNode(node) => {
                            // println!("Traversing to Internal Node at depth: {}, Key: {:?}", node.depth, node.key);
                            current_node = node;
                            depth += 1;
                        },
                        Entry::Leaf(leaf) => {
                            // println!("Found Leaf Node at depth: {}, Key: {:?}", depth, leaf.key);
                            if leaf.key == hashed_key {
                                // The current node contains the matching leaf, so it's already added to the path
                                break; // Found the target leaf node
                            } else {
                                path.clear(); // Key mismatch in leaf node, clear the path
                                break;
                            }
                        }
                    }
                },
                None => {
                    // Child not found, stop the traversal
                    path.clear();
                    break;
                }
            }
        }
    
        Ok(path)
    }
    
    /// Insert a key-value pair into the tree
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>, max_depth: usize) {
        let hashed_key = hash(&key);
        println!("Inserting key: {:?}, hashed: {:?}", key, hashed_key);
    
        let mut current_node = self;
        for depth in 0..max_depth {
            if depth >= hashed_key.len() {
                println!("Reached the end of the hashed key at depth: {}", depth);
                current_node.children.push(Entry::Leaf(LeafNode { key: hashed_key.clone(), value: value.clone() }));
                return;
            }
    
            let prefix = hashed_key[depth];
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

    /// Print the commitments of the tree
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

    /// Check the commitment of all the nodes in the tree
    pub fn check_commitment(
        &self, 
        ck: &<KZG10 as PolynomialCommitment<BlsFr, Poly>>::CommitterKey,
        vk: &<KZG10 as PolynomialCommitment<BlsFr, Poly>>::VerifierKey,
        rng: &mut impl RngCore
    ) -> Result<bool, <KZG10 as PolynomialCommitment<BlsFr, Poly>>::Error> {
        // Recreate the polynomial from the node's data
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
        let labeled_polynomial = ark_poly_commit::LabeledPolynomial::new("poly".to_string(), polynomial, None, None);

        // Select a random point for evaluation
        let point = BlsFr::rand(rng);

        // Step 1: Create an opening proof at the chosen point
        // Prepare labeled polynomial and commitment
        let commitment_ref = self.commitment.as_ref().ok_or_else(|| {
            ark_poly_commit::Error::MissingPolynomial {
                label: "node_commitment".to_string()
            }
        })?;

        let labeled_commitment = LabeledCommitment::new("node_commitment".to_string(), commitment_ref.clone(), None);

        // Generate a random challenge for the proof opening and checking
        let challenge = BlsFr::rand(rng); 

        // open the proof
        let proof = KZG10::open(
            ck,
            std::iter::once(&labeled_polynomial),
            std::iter::once(&labeled_commitment),
            &point,
            challenge,
            std::iter::once(&<KZG10 as PolynomialCommitment<BlsFr, Poly>>::Randomness::empty()), // Assuming empty randomness; adjust if needed
            Some(rng)
        )?;

        // Step 2: Verify the opening proof
        KZG10::check(
            vk,
            std::iter::once(&labeled_commitment),
            &point,
            std::iter::once(labeled_polynomial.evaluate(&point)),
            &proof,
            challenge,
            Some(rng)
        )
    }

    /// Generate a proof for the existence of a key in the Verkle tree.
    pub fn generate_path_proof(&self, key: &[u8]) -> Option<PathProof> {
        let mut current_node = self;
        let mut path: Vec<VerkleNodeProof> = Vec::new();
        let hashed_key = hash(key); // Hash the key if your tree uses hashed keys
        let mut depth = 0; // Initialize depth to 0

        // Loop until a leaf is found or there are no more nodes to check
        while depth < hashed_key.len() {
            let current_byte = hashed_key[depth];
            let child_option = current_node.children.iter().find(|&child| {
                match child {
                    Entry::InternalNode(node) => {
                        node.key.get(0) == Some(&current_byte)
                    },
                    Entry::Leaf(leaf) => {
                        leaf.key == hashed_key
                    },
                    _ => false,
                }
            });

            // Construct node proof for the current node
            let node_proof = VerkleNodeProof {
                key: current_node.key.clone(),
                commitment: current_node.commitment.clone(),
                // Include other necessary data for the proof
            };
            path.push(node_proof);

            match child_option {
                Some(Entry::InternalNode(node)) => {
                    // Move to the next internal node at the next depth
                    current_node = node;
                    depth += 1;
                },
                Some(Entry::Leaf(leaf)) => {
                    // Check if the leaf node's key matches the hashed key
                    if leaf.key == hashed_key {
                        break; // Stop if the target leaf node is found
                    } else {
                        return None; // Return None if the leaf node key doesn't match the hashed key
                    }
                },
                None => {
                    return None; // Return None if no matching child is found
                }
            }
        }

        // Return None if no leaf with the key is found
        if path.last().map_or(true, |p| !matches!(p, VerkleNodeProof { key: _, commitment: _ })) {
            return None;
        }

        Some(PathProof { path })
    }

    /// Generate a proof of membership for a given key within the Verkle tree.
    pub fn proof_of_membership(
        &self,
        key: &[u8],
    ) -> Option<PathProof> {
        // Retrieve the node at the level of the tree using the raw key
        let node = self.get(key.to_vec());
    
        // Generate the Verkle proof based on whether the key is found or not
        let proof = self.generate_path_proof(key);
    
        match node {
            Some(_) => println!("Key found, generating proof of membership."),
            None => println!("Key not found, generating proof of non-membership."),
        }
    
        proof
    }
}


/// VerkleTree structure
pub struct VerkleTree {
    pub root: Node,
    pub params: (
        <KZG10 as PolynomialCommitment<BlsFr, Poly>>::UniversalParams,
        <KZG10 as PolynomialCommitment<BlsFr, Poly>>::CommitterKey,
        <KZG10 as PolynomialCommitment<BlsFr, Poly>>::VerifierKey,
    ),
    pub max_depth: usize,
}

/// VerkleTree functions
impl VerkleTree {

    /// Create a new VerkleTree with the given depth and branching factor
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
    
    /// Print the tree
    pub fn print_tree(&self) {
        self.root.print_tree();
    }
    
    /// Get the value for a given key
    pub fn get(&self, key: Vec<u8>) -> Option<Vec<u8>> {
        self.root.get(key)
    }

    /// Insert a key-value pair into the tree
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.root.insert(key, value, self.max_depth);

    }

    /// Set the commitments for the entire tree
    pub fn set_commitments(&mut self) -> Result<(), <KZG10 as PolynomialCommitment<BlsFr, Poly>>::Error> {
        let committer_key = &self.params.1;
        let mut rng = rand::thread_rng();

        // Start the commitment setting process from the root node
        self.root.set_commitments_recursive(committer_key, &mut rng)
    }

    /// Print the commitments of the tree
    pub fn print_commitments(&self) {
        println!("Tree Commitments:");
        self.root.print_commitments(0);
    }

    /// Verifies the commitments of the entire tree.
    pub fn check_commitments(&self) -> Result<bool, <KZG10 as PolynomialCommitment<BlsFr, Poly>>::Error> {
        let ck = &self.params.1; // Committer key
        let vk = &self.params.2; // Verifier key
        let mut rng = thread_rng(); // Or your preferred RNG

        self.root.check_commitment(ck, vk, &mut rng)
    }

    /// Verifies the commitment of a specific key.
    pub fn verify_path(&self, key: Vec<u8>) -> Result<bool, <KZG10 as PolynomialCommitment<BlsFr, Poly>>::Error> {
        let path_result = self.root.get_path(&key);
        let ck = &self.params.1; // Committer key
        let vk = &self.params.2; // Verifier key
        let mut rng = thread_rng(); // Or your preferred RNG

        match path_result {
            Ok(path) => {
                for node in path {
                    if !node.check_commitment(ck, vk, &mut rng)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            },
            Err(error) => {
                println!("Error: {}", error);
                // Handle the case where the path is None (key not found)
                Ok(false)
            }
        }
    }

    /// Generate a proof for a given key within the Verkle tree.
    pub fn generate_proof_for_key(&self, key: &[u8]) -> Option<PathProof> {
        self.root.generate_path_proof(key)
    }

    /// Generate a proof of membership for a given key within the Verkle tree.
    pub fn proof_of_membership_for_key(
        &self,
        key: &[u8],
    ) -> Option<PathProof> {
        self.root.proof_of_membership(key)
    }

    /// Check the commitment for a specific key
    pub fn check_commitment_for_key(
        &self,
        key: &[u8]
    ) -> Result<bool, <KZG10 as PolynomialCommitment<BlsFr, Poly>>::Error> {
        let ck = &self.params.1; // Committer key
        let vk = &self.params.2; // Verifier key
        let mut rng = thread_rng(); // RNG
    
        // Find the path to the node with the given key
        let path = match self.root.get_path(key) {
            Ok(path) => path,
            Err(error) => {
                println!("Error getting path: {}", error);
                return Err(ark_poly_commit::Error::MissingPolynomial {
                    label: format!("Key: {}", hex::encode(key))
                });
            }
        };
    
        // Check if the last node in the path corresponds to the key
        if let Some(node) = path.last() {
            // Proceed with the commitment check
            match node.check_commitment(ck, vk, &mut rng) {
                Ok(valid) => Ok(valid),
                Err(e) => {
                    println!("Error checking commitment for key {:?}: {:?}", hex::encode(key), e);
                    Err(e)
                },
            }
        } else {
            // Path not found to the key
            Err(ark_poly_commit::Error::MissingPolynomial {
                label: format!("Key: {}", hex::encode(key))
            })
        }
    }
    
    
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup_tree() -> VerkleTree {
        let mut rng = rand::thread_rng();
        let degree = 256;
    
        // Set up the parameters, committer key, and verifier key
        let (params, committer_key, verifier_key) = setup(degree, None, &mut rng).unwrap();
    
        let depth = 40;
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

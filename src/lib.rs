use ark_ec::models::{short_weierstrass_jacobian::GroupAffine as SWAffine, SWModelParameters};
use ark_ec::PairingEngine;
use ark_ff::{Field, PrimeField, quadratic_extension};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::marlin::marlin_pc::MarlinKZG10;
use ark_poly_commit::{Polynomial, PolynomialCommitment, PolynomialLabel, LabeledPolynomial, LabeledCommitment};
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
    
    /// Inserts a key-value pair into the tree from the current node 
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

// TODO: Define a struct VerkleProof, which will be a Verkle opening proof for multiple field
// elements
pub struct VerkleProof<F: Field, P: Polynomial<F>, PC: PolynomialCommitment<F, P>> {
    sibling_commitments: Vec<PC::Commitment>, // the commitments of the siblings of each level of the path
    path: Vec<u8>, // the path from the root to the leaf (the hash of the key)
    combined_commitment: PC::Commitment, // root commitment
}

impl<F, P, PC> VerkleTree<F, P, PC>
where
    F: Field,
    P: Polynomial<F>,
    PC: PolynomialCommitment<F, P>,
{
    /// Create a verkle tree with the given depth and branching factor
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
    
    /// Prints the tree
    pub fn print_tree(&self) {
        self.root.print_tree();
    }
    
    /// Returns the value of the key if it exists in the tree
    pub fn get(&self, key: Vec<u8>) -> Option<Vec<u8>> {
        self.root.get(key)
    }

    /// Inserts a key-value pair into the tree
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.root.insert(key, value, self.max_depth);

    }

    /// Returns the depth of the tree
    pub fn depth(&self) -> usize {
        self.max_depth
    } 

    /// Returns the polynomial commitment at the root of the tree
    pub fn root(&self) -> PC::Commitment {
        self.root.commitment.clone().unwrap()
    }

    pub fn set_commitments(&self, ck: &PC::CommitterKey) {
        // 0.1 walk through each level of the tree from depth 32 (length of a sha256 hash of the key/address) to root, 
            // setting the commitments as we move from node to node within each depth level, only moving up a depth level after
            // all nodes at the current depth level have been committed to

        // to do this, we need to be able to track the internal/leaf nodes at each level of the tree
        // I'm thinking we can do this through the keys of the nodes that were inserted into the tree.
        // For example, each of the nodes has a key that is a subset of the 32 u8 hash of the address from the test_data.txt file. 
        // My initial idea is not the most efficient, but if we store the hashes of the keys, we'll be able to use a modified get() method 
        // to retrieve the nodes at the level of the tree corresponding with the last element in the hash. For example, if we use the
        // complete hash of the address, we'll be able to retrieve the corresponding leaf node. If we use the hash of the first 31 bytes,
        // we'll be able to retrieve the corresponding internal node which will be the parent of the prior leaf node. 

        // For this to work, we will therefore need to iterate through all of the hashes, setting commitments for each get(hash) call and 
        // storing a new search_hash which will be the sha_256_hash[0..i-1]. Once the list of hashes for this level of the tree/this length of substring,
        // we can move on to the next level of the tree which necessitates a new search and commit phase

        // ~~~~~~~~~~~~~~~~~~~ How to create commitments ~~~~~~~~~~~~~~~~~~~~~~~~
        // All of the following will be one iteration of a loop which will need to apply to all nodes in the tree iterated through as described above
        //
        // 1. we need to represent each node as a polynomial of degree d-1 for d children for each node. 
        // 1.1 to do this, we need to create a method that will turn a node into a polynomial using the Polynomal<F> P trait
        // 1.2 to create a polynomial, we can utilize the ark_works method "ark_poly_commit::DenseUVPolynomial::from_coefficients_vec(coefficients)"
        // 1.2.1 the documentation to this method can be found here: 
            // https://docs.rs/ark-poly-commit/latest/ark_poly_commit/trait.DenseUVPolynomial.html#tymethod.from_coefficients_vec
        // 1.3 we will need to create a vector of coefficients for each node to provide as input for the above function.
        // 1.3.1 I am wondering what to pass in as the coefficients for each node in order to create the polynomial. We could either use the value of 
            // the children nodes or the hash value (the prefix) of the children nodes, whichever is easier to implement.
        // 1.3.2 Regardless of what we use as the coefficients, we need to create a vector of coefficients with the commiting node's value/prefix
            // as the first element in the vector
        // 1.3.3 When the vector of coefficients is created, we can then utilize the from_coefficients_vec(coefficients) method to create a polynomial 
        //
        // 2. I believe that we should be able to use the ark_poly_commit::commit(&committer_key, &polynomial, rng) method to create commitments
        // 2.1 we need to apply this method to all the nodes to compute their commitments.
        // 2.1.1 I believe that we can traverse the tree from depth d to root, finishing the creation of all commitments at depth d before moving to 
            // depth d-1 by utilizing the search pattern I described above using the hashed-keys of the nodes.
        // 2.1.2 we can use the from_coefficients_vec(coefficients) method to create a polynomial for each node.
            // We can then use the commit(&committer_key, &polynomial, rng) method to create a commitment for each node which will be stored in the
            // node.commitment field
        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        panic!("TODO");

    }

    /// Open the verkle tree at the given set of positions
    pub fn open_commitments(&self, position: Vec<usize>) -> Option<(Vec<F>, Vec<VerkleProof<F, P, PC>>)> {
        // I believe that we can use the provided method ark_poly_commit::PolynomialCommitment::bath_open() which takes the following: 
            // ck: &Self::ComitterKey, 
            // labeled_polynomials:  

        // ~~~~~~~~~~~~~~~~~ How to make a VerkleProof ~~~~~~~~~~~~~~~~~~~~~~~~
        // We have a VerkleProof struct that was given by the O1 Labs team. It has three fields: sibling_commitments, path, and combined_commitment
        //
        // sibling_commitments: vector of commitments to the siblings of each level of the path
        // path: the path from the root to the leaf (the hash of the key)
        // combined_commitment: the root commitment 
        //
        // We will then need to create a sibling_commitments vector element for our Node object. 
        // This will be a vector of commitments to the siblings of each node of each level of the path.
        // We will also need to create a method that will return the sibling commitments at each level of the path
        // This will be a vector of vectors of commitments at each level of the path that the verifier will use in conjunction
        // with the given path and combined commitment to verify the proof of membership.
        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        panic!("TODO");
    }

    /// Prove that the given value is in the tree at the given position
    pub fn check_commitments(&self, position: Vec<usize>, value: Vec<F>, proof: Vec<VerkleProof<F, P, PC>>) -> bool {
        panic!("TODO");
    }

    pub fn proof_of_membership() {
        // Before this method is called, a verkle tree must have already been created and set_commitments() should have already been executed

        // first we need to ask the user for a key/address to search for
        // then we need to hash the key/address
        // then we need to use the get() method to retrieve the node at the level of the tree corresponding with the last element in the hash
        // then we need to find a way to communicate to the open_commitments() method which node to open which is communicated based on 

        panic!("TODO");
    }
}


pub trait ToFieldElements<F: Field> {
    // Just stipulates a method for converting a polynomial commitment into an vector of field
    // elements.
    fn to_field_elements(&self) -> Vec<F>;
}

impl<'a, 'b, P, E> ToFieldElements<P::ScalarField>
    for ark_poly_commit::marlin::marlin_pc::Commitment<E>
where
    P: SWModelParameters,
    E: PairingEngine<Fq = P::BaseField, G1Affine = SWAffine<P>>,
    P::ScalarField: PrimeField,
    P::BaseField: PrimeField<BigInt = <P::ScalarField as PrimeField>::BigInt>,
{
    fn to_field_elements(&self) -> Vec<P::ScalarField> {
        // We don't use degree bounds, and so ignore the shifted part of the commitments
        let _ = self.shifted_comm;
        [self.comm.0.x, self.comm.0.y]
            .iter()
            .map(|a| P::ScalarField::from_repr(a.into_repr()).unwrap())
            .collect()
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

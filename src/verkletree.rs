use ark_poly::UVPolynomial;
use ark_ff::fields::PrimeField;
use ark_ff::ToBytes;
use ark_ec::PairingEngine; 
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::{marlin_pc::MarlinKZG10, ipa_pc::CommitterKey}; 
use ark_poly_commit::{PolynomialCommitment, PolynomialLabel};
use ark_std::rand::Rng;
use ark_bls12_381::Bls12_381;
use sha2::{Sha256, Digest};
use ark_poly_commit::LabeledPolynomial;
use ark_poly_commit::marlin_pc::{UniversalParams, VerifierKey};
use ark_ec::bls12::Bls12;
use ark_bls12_381::Parameters;
use ark_poly_commit::LabeledCommitment;
use ark_std::One;
use ark_serialize::Write;
// error[E0599]: no method named `compute_commitment` found for struct `VerkleTree` in the current scope
//   --> src/main.rs:52:23
//    |
// 52 |     let commit = tree.compute_commitment();
//    |                       ^^^^^^^^^^^^^^^^^^ method not found in `VerkleTree<Fp256<FrParameters>, ..., ...>`
//    |
//    = note: the full type name has been written to '/Users/michaelgoldfarb/Desktop/VerkleTreeRust/target/debug/deps/VerkleTreeRust-151a4b062914e7c3.long-type-15368198073706428945.txt'

// error[E0599]: no method named `proof_generation` found for struct `VerkleTree` in the current scope
//   --> src/main.rs:56:33
//    |
// 56 | ...of_for_wallet = tree.proof_generation(key_wallet.clone()).expect("Pro...
//    |                         ^^^^^^^^^^^^^^^^ method not found in `VerkleTree<Fp256<FrParameters>, ..., ...>`
//    |
//    = note: the full type name has been written to '/Users/michaelgoldfarb/Desktop/VerkleTreeRust/target/debug/deps/VerkleTreeRust-151a4b062914e7c3.long-type-15368198073706428945.txt'

// error[E0599]: no method named `verify` found for struct `VerkleTree` in the current scope
//   --> src/main.rs:61:35
//    |
// 61 | ...s_verified_wallet = tree.verify(&commit, key_wallet.clone(), vec![13,...
//    |                             ^^^^^^ method not found in `VerkleTree<Fp256<FrParameters>, ..., ...>`

// Set up for Polynomial Commitments using ark library
type Fr = <Bls12_381 as PairingEngine>::Fr;
type Poly = DensePolynomial<Fr>;

type KZG10 = MarlinKZG10<Bls12_381, Poly>;

pub fn setup<R: Rng>(degree: usize, rng: &mut R) -> (<KZG10 as PolynomialCommitment<Fr, Poly>>::UniversalParams, <KZG10 as PolynomialCommitment<Fr, Poly>>::CommitterKey, <KZG10 as PolynomialCommitment<Fr, Poly>>::VerifierKey) {
    let params = KZG10::setup(degree, None, rng).unwrap();
    let (committer_key, verifier_key) = KZG10::trim(&params, degree, 0, None).unwrap();
    (params, committer_key, verifier_key)
}


// hash function (SHA-256 most likely)
pub fn hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// lets set a fixed width of 256 bits (similar to vitalik's implementation)
const MAX_CHILDREN: usize = 256;

// Node structure
pub struct Node {
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
    pub children: Vec<Node>,
    pub commitment: Option<<KZG10 as PolynomialCommitment<Fr, Poly>>::Commitment>,
}


// NEXT STEPS: 
// - create function for commitments using ark library
impl Node {
    pub fn new(key: Vec<u8>) -> Self {
        Node {
            key: hash(&key),
            value: None,
            children: Vec::new(),
            commitment: None,  // Initialize the commitment field to None
        }
    }

    pub fn split_and_insert(&mut self, new_node: Node) {
        let mid = MAX_CHILDREN / 2;
        let mut new_internal_node = Node::new(self.children[mid].key.clone());
        new_internal_node.children = self.children.split_off(mid + 1);
        new_internal_node.children.push(new_node);
        self.key = new_internal_node.children[0].key.clone();
        self.children.push(new_internal_node);
        // Sort the children by their keys
        self.children.sort_by(|a, b| a.key.cmp(&b.key));
    }

    pub fn insert(&mut self, mut key: Vec<u8>, value: Vec<u8>) {
        if key.is_empty() {
            self.value = Some(value);
            return;
        }

        let prefix = key.remove(0);
        let hashed_prefix = hash(&vec![prefix]);
        let position = self.children.binary_search_by(|child| child.key.cmp(&hashed_prefix));
        match position {
            Ok(index) => {
                self.children[index].insert(key, value);
            },
            Err(index) => {
                let mut new_node = Node::new(vec![prefix]);
                new_node.insert(key.clone(), value.clone());
                if self.children.len() < MAX_CHILDREN {
                    self.children.insert(index, new_node);
                } else if self.children.len() == MAX_CHILDREN {
                    self.split_and_insert(new_node);
                    // Ensure the children are sorted after the split_and_insert operation
                    self.children.sort_by(|a, b| a.key.cmp(&b.key));
                }
            }
        }
    }

    pub fn compute_commitment(&mut self, committer_key: &<KZG10 as PolynomialCommitment<Fr, Poly>>::CommitterKey) -> <KZG10 as PolynomialCommitment<Fr, Poly>>::Commitment {
        // If the commitment is already computed and stored, return it.
        if let Some(commitment) = &self.commitment {
            println!("Using stored commitment: {:?}", commitment);
            return commitment.clone();
        }

        // If the node is a leaf (no children), compute the commitment based on its value.
        if self.children.is_empty() {
            let value_as_bytes = self.value.as_ref().unwrap_or(&Vec::new()).clone();
            let value_hash = hash(&value_as_bytes);
            let fr_value = Fr::from_le_bytes_mod_order(&value_hash);
            let polynomial = Poly::from_coefficients_vec(vec![fr_value]); 
            let (commitments, _) = KZG10::commit(committer_key, &[LabeledPolynomial::new("label".into(), polynomial, None, None)], None).unwrap();
            self.commitment = Some(commitments[0].commitment().clone());
            println!("Leaf node commitment: {:?}", self.commitment);
            return self.commitment.as_ref().unwrap().clone();
        }

        // If the node has children, compute the commitment based on its children's commitments.
        let child_commitments: Vec<_> = self.children.iter_mut().map(|child| child.compute_commitment(committer_key)).collect();
        let concatenated_bytes: Vec<u8> = child_commitments.iter().flat_map(|commitment| {
            let mut bytes = Vec::new();
            commitment.write(&mut bytes).unwrap();
            bytes
        }).collect();

        let combined_hash = hash(&concatenated_bytes);
        let fr_value = Fr::from_le_bytes_mod_order(&combined_hash);
        let polynomial = Poly::from_coefficients_vec(vec![fr_value]);
        let (commitments, _) = KZG10::commit(committer_key, &[LabeledPolynomial::new("label".into(), polynomial, None, None)], None).unwrap();
        self.commitment = Some(commitments[0].commitment().clone());
        println!("Internal node commitment: {:?}", self.commitment);
        self.commitment.as_ref().unwrap().clone()
    }

    pub fn verify_commitment(
        &self,
        commitment: &<KZG10 as PolynomialCommitment<Fr, Poly>>::Commitment,
        key: Vec<u8>,
        value: Vec<u8>,
        siblings: &Vec<(<KZG10 as PolynomialCommitment<Fr, Poly>>::Commitment, bool)>, // Use the fully-qualified path
        committer_key: &<KZG10 as PolynomialCommitment<Fr, Poly>>::CommitterKey,
    ) -> bool {
        // Compute the commitment of the key-value pair
        let value_hash = hash(&value);
        let fr_value = Fr::from_le_bytes_mod_order(&value_hash);
        let polynomial = Poly::from_coefficients_vec(vec![fr_value]);
        let (commitments, _) = KZG10::commit(committer_key, &[LabeledPolynomial::new("label".into(), polynomial, None, None)], None).unwrap();
        let mut current_commitment = commitments[0].commitment().clone();
    
        // Reconstruct the path to the root using the siblings
        for (sibling, is_left) in siblings.iter().rev() {
            let mut concatenated_bytes = Vec::new();
            if *is_left {
                sibling.write(&mut concatenated_bytes).unwrap();
                current_commitment.write(&mut concatenated_bytes).unwrap();
            } else {
                current_commitment.write(&mut concatenated_bytes).unwrap();
                sibling.write(&mut concatenated_bytes).unwrap();
            }
            println!("Current commitment: {:?}", current_commitment);
            println!("Combining with sibling: {:?}", sibling);
            let combined_hash = hash(&concatenated_bytes);
            let fr_combined = Fr::from_le_bytes_mod_order(&combined_hash);
            let polynomial_combined = Poly::from_coefficients_vec(vec![fr_combined]);
            let (combined_commitments, _) = KZG10::commit(committer_key, &[LabeledPolynomial::new("label".into(), polynomial_combined, None, None)], None).unwrap();
            current_commitment = combined_commitments[0].commitment().clone();
        }
    
        // Check if the reconstructed root matches the provided commitment
        println!("Reconstructed Commitment: {:?}", current_commitment);
        println!("Provided Commitment: {:?}", commitment);
        current_commitment == *commitment
    }
    
    
    pub fn proof_generation(&mut self, key: Vec<u8>, committer_key: &<KZG10 as PolynomialCommitment<Fr, Poly>>::CommitterKey) -> Option<Vec<(<KZG10 as PolynomialCommitment<Fr, Poly>>::Commitment, bool)>> {
        let mut current_node: &mut Node = self;
        let mut path: Vec<(<MarlinKZG10<Bls12<ark_bls12_381::Parameters>, DensePolynomial<<Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr>> as PolynomialCommitment<<Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr, DensePolynomial<<Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr>>>::Commitment, bool)> = vec![];
        
        // Traverse the tree to find the leaf node for the given key
        // Traverse the tree to find the leaf node for the given key
        let mut partial_key = key.clone();
        while !partial_key.is_empty() {
            let prefix = partial_key.remove(0);
            let hashed_prefix = hash(&vec![prefix]);
            let position = current_node.children.binary_search_by(|child| child.key.cmp(&hashed_prefix));
            
            match position {
                Ok(index) => {
                    // If the node exists, record the siblings and move deeper
                    for (i, sibling) in current_node.children.iter_mut().enumerate() {
                        if i != index {
                            let sibling_commitment = sibling.compute_commitment(committer_key);
                            path.push((sibling_commitment.clone(), i < index)); // Include position information
                            println!("Adding sibling commitment at index {}: {:?}", i, sibling_commitment);
                        }
                    }
                    
                    current_node = &mut current_node.children[index];
                },
                Err(_) => return None, // Return None if the key doesn't exist
            }
        }

        println!("Proof for key {:?}: {:?}", key, path);
        Some(path)
    }
    
    
}

pub struct VerkleTree {
    pub root: Node,
    pub params: (
        <KZG10 as PolynomialCommitment<Fr, Poly>>::UniversalParams, 
        <KZG10 as PolynomialCommitment<Fr, Poly>>::CommitterKey, 
        <KZG10 as PolynomialCommitment<Fr, Poly>>::VerifierKey
    ),
}


impl VerkleTree {

    pub fn proof_generation(&mut self, key: Vec<u8>) -> Option<Vec<(<KZG10 as PolynomialCommitment<Fr, Poly>>::Commitment, bool)>> {
        self.root.proof_generation(key, &self.params.1)
    }

    pub fn verify(
        &self,
        commitment: &<KZG10 as PolynomialCommitment<Fr, Poly>>::Commitment,
        key: Vec<u8>,
        value: Vec<u8>,
        siblings: &Vec<(<KZG10 as PolynomialCommitment<Fr, Poly>>::Commitment, bool)>,
    ) -> bool {
        let committer_key = &self.params.1;
        self.root.verify_commitment(commitment, key, value, siblings, committer_key)
    }

    pub fn new(initial_key: Option<Vec<u8>>) -> Self {
        let params = setup(MAX_CHILDREN, &mut rand::thread_rng());
        VerkleTree {
            root: Node::new(initial_key.unwrap_or_else(Vec::new)),
            params,
        }
    }
    

    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.root.insert(key, value);
    }

    pub fn compute_commitment(&mut self) -> <KZG10 as PolynomialCommitment<Fr, Poly>>::Commitment {
        self.root.compute_commitment(&self.params.1)
    }

    pub fn verify_commitment(
        &self,
        commitment: &<KZG10 as PolynomialCommitment<Fr, Poly>>::Commitment,
        key: Vec<u8>,
        value: Vec<u8>,
        siblings: &Vec<(<KZG10 as PolynomialCommitment<Fr, Poly>>::Commitment, bool)>,
    ) -> bool {
        let committer_key = &self.params.1;
        self.root.verify_commitment(commitment, key, value, siblings, committer_key)
    }

    pub fn get(&self, key: Vec<u8>) -> Option<Vec<u8>> {
        self.root.get_value(&key);
    }

    pub fn print_tree(&self) {
        self.root.print_tree();
    }
    
    
}
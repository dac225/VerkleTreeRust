use ark_poly::UVPolynomial;
use ark_ff::fields::PrimeField;
use ark_ff::ToBytes;
use ark_ec::PairingEngine; 
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10; 
use ark_poly_commit::PolynomialCommitment;
use ark_std::rand::Rng;
use ark_bls12_381::Bls12_381;
use sha2::{Sha256, Digest};
use ark_poly_commit::LabeledPolynomial;


// Set up for Polynomial Commitments using ark library
type Fr = <Bls12_381 as PairingEngine>::Fr;
type Poly = DensePolynomial<Fr>;

type KZG10 = MarlinKZG10<Bls12_381, Poly>;

pub fn setup<R: Rng>(degree: usize, rng: &mut R) -> (<KZG10 as PolynomialCommitment<Fr, Poly>>::UniversalParams, <KZG10 as PolynomialCommitment<Fr, Poly>>::CommitterKey) {
    let params = KZG10::setup(degree, None, rng).unwrap();
    let (committer_key, _) = KZG10::trim(&params, degree, 0, None).unwrap();
    (params, committer_key)
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
    pub key: Vec<u8>, // This key will now store the hashed prefix.
    pub value: Option<Vec<u8>>,
    pub children: Vec<Node>,
}

// NEXT STEPS: 
// - create function for commitments using ark library
impl Node {
    pub fn new(key: Vec<u8>) -> Self {
        Node {
            key: hash(&key), // The passed key is hashed during node creation.
            value: None,
            children: Vec::new(),
        }
    }
    pub fn split_and_insert(&mut self, new_node: Node) {
        // Find the midpoint of the children and create a new internal node
        let mid = MAX_CHILDREN / 2;
        let mut new_internal_node = Node::new(self.children[mid].key.clone());

        // Move half the children to the new internal node
        new_internal_node.children = self.children.split_off(mid + 1); // +1 to keep mid in current node
        new_internal_node.children.push(new_node);

        // Re-assign the current node's key to be the same as the new internal node's first child's key
        self.key = new_internal_node.children[0].key.clone();

        // Attach the new internal node as a child of the current node
        self.children.push(new_internal_node);
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
                }
            }
        }
    }   

    pub fn compute_commitment(&self, committer_key: &<KZG10 as PolynomialCommitment<Fr, Poly>>::CommitterKey) -> <KZG10 as PolynomialCommitment<Fr, Poly>>::Commitment {
        if self.children.is_empty() {
            let value_as_bytes = self.value.as_ref().map_or_else(Vec::new, |v| v.clone());
            let value_hash = hash(&value_as_bytes);
    
            let fr_value = Fr::from_le_bytes_mod_order(&value_hash);
            
            let polynomial = Poly::from_coefficients_vec(vec![fr_value]);
            
            let (commitments, _) = KZG10::commit(committer_key, &[LabeledPolynomial::new("label".into(), polynomial, None, None)], None).unwrap();
            return commitments[0].commitment().clone();
        }
    
        let child_commitments: Vec<_> = self.children.iter().map(|child| child.compute_commitment(committer_key)).collect();
        let concatenated_bytes: Vec<u8> = child_commitments.iter().flat_map(|commitment| {
            let mut bytes = Vec::new();
            commitment.write(&mut bytes).unwrap();
            bytes
        }).collect();
        let combined_hash = hash(&concatenated_bytes);
        
        let fr_value = Fr::from_le_bytes_mod_order(&combined_hash);
        let polynomial = Poly::from_coefficients_vec(vec![fr_value]);
        let (commitments, _) = KZG10::commit(committer_key, &[LabeledPolynomial::new("label".into(), polynomial, None, None)], None).unwrap();
        commitments[0].commitment().clone()
    }
    
    
    
}

// VerkleTree structure updated to store the universal parameters
pub struct VerkleTree {
    pub root: Node,
    pub params: (<KZG10 as PolynomialCommitment<Fr, Poly>>::UniversalParams, <KZG10 as PolynomialCommitment<Fr, Poly>>::CommitterKey),
}


impl VerkleTree {
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

    pub fn commitment(&self) -> <KZG10 as PolynomialCommitment<Fr, Poly>>::Commitment {
        self.root.compute_commitment(&self.params.1) 
    }
    
}






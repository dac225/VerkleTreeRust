use ark_ec::models::{short_weierstrass_jacobian::GroupAffine as SWAffine, SWModelParameters};
use ark_ec::PairingEngine;
use ark_ff::{Field, PrimeField};
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
            key: hash(&key),
            children: Vec::new(),
            commitment: None,
            max_children,
            depth,
        }
    }

    pub fn get(&self, key: Vec<u8>) -> Option<Vec<u8>> {
        let mut current_node = self;
    
        for depth in 0..key.len() {
            let prefix = key[depth];
            let position = current_node.children.iter().position(|child| match child {
                Entry::InternalNode(node) => node.key[0] == prefix,
                Entry::Leaf(leaf) => leaf.key[depth] == prefix,
            });
    
            match position {
                Some(index) => {
                    match &current_node.children[index] {
                        Entry::InternalNode(node) => {
                            current_node = node;
                        },
                        Entry::Leaf(leaf) => {
                            if leaf.key == key {
                                return Some(leaf.value.clone());
                            } else {
                                return None;
                            }
                        }
                    }
                },
                None => {
                    return None;
                }
            }
        }
    
        None
    }    
    
    pub fn split_and_insert(&mut self, new_node: Node<F, P, PC>) {
        let mid = self.max_children / 2;
        let mut new_internal_node = Node::new(new_node.key.clone(), self.max_children, self.depth);
    
        new_internal_node.children.push(Entry::InternalNode(new_node));
    
        self.key = new_internal_node.key.clone();
        self.children = vec![Entry::InternalNode(new_internal_node)];
        println!("Split and Inserted Internal Node at Depth {}: Key: {:?}", self.depth, self.key);
    }
    
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>, max_depth: usize) {
        println!("Inserting key of length: {}", key.len());
        println!("Current key: {:?}", key);
    
        let mut current_node = self;
    
        for depth in 0..max_depth {
            if depth == key.len() {
                let new_leaf = Entry::Leaf(LeafNode { key: key.clone(), value });
                println!("Created a new LeafNode for key: {:?}", key);
                current_node.children.push(new_leaf);
                return;
            }
    
            let prefix = key[depth];
            let position = current_node.children.iter().position(|child| match child {
                Entry::InternalNode(node) => node.key[0] == prefix,
                Entry::Leaf(leaf) => leaf.key[depth] == prefix,
            });
    
            match position {
                Some(index) => {
                    let child = current_node.children.remove(index);
                    match child {
                        Entry::InternalNode(mut node) => {
                            current_node.children.insert(index, Entry::InternalNode(node)); // Reinsert the node
                            current_node = match current_node.children.get_mut(index).unwrap() {
                                Entry::InternalNode(node) => node,
                                _ => panic!("Expected an InternalNode!"),
                            };
                        },
                        Entry::Leaf(leaf) => {
                            if leaf.key == key {
                                current_node.children.insert(index, Entry::Leaf(LeafNode { key: key.clone(), value }));
                            } else {
                                let mut new_internal_node = Node::new(vec![prefix], current_node.max_children, depth + 1);
                                println!("Created Internal Node at depth: {}", new_internal_node.depth);
    
                                new_internal_node.children.push(Entry::Leaf(leaf));
                                new_internal_node.children.push(Entry::Leaf(LeafNode { key: key.clone(), value }));
                                println!("Created a new LeafNode for key: {:?}", key);
    
                                current_node.children.insert(index, Entry::InternalNode(new_internal_node));
                            }
                            return;
                        }
                    }
                },
                None => {
                    let new_node = Node::new(vec![prefix], current_node.max_children, depth + 1);
                    println!("Created Internal Node at depth: {}", new_node.depth);
                    current_node.children.push(Entry::InternalNode(new_node));
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
        let committer_key = MarlinKZG10::<Bls12_381, DensePolynomial<<Bls12_381 as ark_ec::PairingEngine>::Fr>>::trim(&params, degree, 0, None).unwrap().0;

        let depth = 16;
        let branching_factor = 256;

        VerkleTree::new(committer_key, depth, branching_factor).expect("Failed to create VerkleTree")
    }

    #[test]
    fn test_insert_and_get_single_value() {
        let mut tree = setup_tree();

        let key = hex::decode("4cc").expect("Failed to decode hex string");
        let value = vec![13, 14, 15];

        tree.insert(key.clone(), value.clone());

        let retrieved_value = tree.get(key.clone());
        assert_eq!(retrieved_value, Some(value));
    }
    #[test]
    fn test_insert_and_get_multiple_values() {
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

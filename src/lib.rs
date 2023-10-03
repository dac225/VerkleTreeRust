use ark_ec::models::{short_weierstrass_jacobian::GroupAffine as SWAffine, SWModelParameters};
use ark_ec::PairingEngine;
use ark_ff::{Field, PrimeField};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::marlin::marlin_pc::MarlinKZG10;
use ark_poly_commit::{Polynomial, PolynomialCommitment, PolynomialLabel};
use sha2::{Sha256, Digest}; // Explicitly import the Digest trait
use rand::Rng;
use ark_bls12_381::Bls12_381;

// Set up for Polynomial Commitments using ark library
type BlsFr = <Bls12_381 as PairingEngine>::Fr;
type Poly = DensePolynomial<BlsFr>;

type KZG10 = MarlinKZG10<Bls12_381, Poly>;

pub fn setup<R: Rng>(degree: usize, rng: &mut R) -> (
    <KZG10 as PolynomialCommitment<BlsFr, Poly>>::UniversalParams,
    <KZG10 as PolynomialCommitment<BlsFr, Poly>>::CommitterKey,
    <KZG10 as PolynomialCommitment<BlsFr, Poly>>::VerifierKey,
) {
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

// Node structure
pub struct Node<F, P, PC>
where
    F: Field,
    P: Polynomial<F>,
    PC: PolynomialCommitment<F, P>,
{
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
    pub children: Vec<Node<F, P, PC>>,
    pub commitment: Option<<PC as PolynomialCommitment<F, P>>::Commitment>,
    pub max_children: usize,
    pub depth: usize, // Added depth field to keep track of node depth
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
            value: None,
            children: Vec::new(),
            commitment: None,
            max_children,
            depth,
        }
    }

    pub fn split_and_insert(&mut self, new_node: Node<F, P, PC>) {
        let mid = self.max_children / 2;
        let mut new_internal_node =
            Node::new(self.children[mid].key.clone(), self.max_children, self.depth);
        new_internal_node.children = self.children.split_off(mid + 1);
        new_internal_node.children.push(new_node);
        self.key = new_internal_node.children[0].key.clone();
        self.children.push(new_internal_node);
        self.children.sort_by(|a, b| a.key.cmp(&b.key));
    }

    pub fn insert(&mut self, mut key: Vec<u8>, value: Vec<u8>, max_depth: usize) {
        if self.depth >= max_depth {
            // Reached the maximum depth, store the value here.
            self.value = Some(value);
            return;
        }

        if key.is_empty() {
            self.value = Some(value);
            return;
        }

        let prefix = key.remove(0);
        let hashed_prefix = hash(&vec![prefix]);
        let position = self.children.binary_search_by(|child| child.key.cmp(&hashed_prefix));
        match position {
            Ok(index) => {
                self.children[index].insert(key, value, max_depth);
            }
            Err(index) => {
                let mut new_node = Node::new(vec![prefix], self.max_children, self.depth + 1); // Increment depth
                new_node.insert(key.clone(), value.clone(), max_depth);
                if self.children.len() < self.max_children {
                    self.children.insert(index, new_node);
                } else if self.children.len() == self.max_children {
                    self.split_and_insert(new_node);
                    self.children.sort_by(|a, b| a.key.cmp(&b.key));
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
    ) -> Self {
        let verkle_tree_impl: VerkleTree<F, P, PC> = VerkleTree {
            root: Node::new(vec![], branching_factor, 0), // Initialize with an empty key
            params: setup(branching_factor, &mut rand::thread_rng()),
            max_depth: depth,
        };
        verkle_tree_impl
    }

    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.root.insert(key, value, self.max_depth);
    }
}

# Verkle Tree Rust Implementation
CSE 242 Blockchain Project
## Verkle Perkles
## Team Members:
- Victor Carolino
- David Cueva
- Michael Goldfarb

* To build (in root directory):
    * RUN cargo build

* To run (in root directory):
    * RUN cargo run

## Documentation

### Data Structure and Implementation Explanations

The data structure that we created is a psuedo-verkle-tree written in Rust utilizing the ark_works cryptographic libraries. This README will assume that the reader has some background knowledge of the concept of verkle trees.Using the resources at the bottom of this README as well as the template code for reference provided by O1 Labs, we were able to construct a program which is able to construct a trie on which polynomial commitments are made on each node, excluding leaf nodes, which validate the correctness of random evaluations on said polynomial. 

The difference between our implementation and a true verkle tree is in the definition of the VerkleProof. As referenced in the O1 Labs template code, a VerkleProof must consist of 

1) a combined commitment (the root commitment), 
2) the path (the indices of the inner node parents of the leaf node), 
3) and sibling commitments (all other commitments in the trie). 

With this information, the VerkleProof protocol would reconstruct the commitments of the path with the information revealed by the sibling commitments and the indices provided already opened. This adds a layer of cryptographic security to the polynomial commitments. Our implementation of a VerkleProof consists of

1) a combined commitment (the root commitment),
2) the path (the commitments of the inner node parents of the leaf node),
3) and sibling commitments (all other commitments in the trie).

Notice that the only difference between our implementation and the template code is the substitution of the path indices with the path commitments. Additionally, in inspecting our implementation, the concept of the VerkleProof is only an abstraction of the three necessary arguments above, and can only be found in the main.rs file as the confirmation of correctness of the three sets of commitments. 

### Program Flowchart 
* Program FlowChart: https://www.figma.com/file/ImdcFOgC0cZ2tcqLLat3mc/Untitled?type=whiteboard&node-id=1%3A55&t=HQibDEue6VE54kLH-1

#### 1. First, we must get the vector/list of all addresses and values that need to go into the trie. Then we need to hash the addresses and transform these into nodes that will be entered into the tree. 
#### 2. We then need to set up the universal parameters and trim them to get our prover and verifier keys.
#### 3. Next, we need to set the commitments at all of the nodes in order to prepare the root commitment which depends on all prior commitments.
#### 4. Prompt the user for a key
#### 5-7. In our implementation, and as stated above, the VerkleProof is composed of the root commitment, the path commitments, and the sibling commitments. Rather than create the three sets of commitments, we simply prove the correctness of all commitments in the VerkleTrie using the check_commitments() method. This accomplishes the proof-of-correctness of the combined commitment and sibling commitments. We then use the key to generate the path_commitment of the key, and if it is found, we open and check the path_commitment, returning true if the commitment check succeeds. If the path_commitment cannot be found, an error is thrown, and the validity of the proof-of-non-membership can be validated by the combined_commitment and sibling_commitments as the trie must be valid at the root composed of all sibling_commitments (which coincidentally includes the path_commitment if the user enters a valid key). This allows for proofs-of-non-membership or memebership to be presented with the same implemented functionality regardless of the validity of the key being searched.

* Resources:
    * <https://docs.google.com/document/d/1Nj4i4tbWpEHKHf4WgfI2yS0jCCvZVjPSxqbe1u1c9Jg/edit?usp=sharing>



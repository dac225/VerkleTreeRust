Everything that needs to be done in this Verkle Tree implementation

1. Creation of Verkle Tree
    1. Insertion/Creation of a Node
        1. 2 types of Nodes
            * Leaf node
                key: sha256 hash of the key
                value: whatever value wants to be inserted
            * Inner node
                prefix:
                vector of nodes:
            * How do we determine what node is which then?
                * The crucial function in a verkle tree that will be affected by this question will be the insert function
                * [Three-possible-cases-for-insert]
                * Note: insertions will always create a new leaf node and may or may not turn an existing leaf node into an inner node
                * When a leaf node is made into an inner node, it will need to compute a commitment to its new set of children nodes
                    * insert from empty tree
                        * we will take the first byte from the hash of the key and place the KV pair into its respective node 
                    * insert on no collision 
                        * same as inserting from empty tree
                    * insert on collision on height h_c which is equivilent to the i'th byte of the KV's Key hash for i..32 bytes in a sha-256 hash
                        * we need to make the leaf node an inner node and have the two nodes sorted based on their h_c+1 byte 
    * KEY POINT from Vitalik Verkle article
        * "[To-edit-the-tree], we need to 'walk up the tree' from the leaf to the root, changing the intermediate commitment at each step to reflect the change that happened lower down.
        * Fortunately, we don't have to re-compute each commitment from scratch. Instead, we take advantage of the homomorphic property:
            * given a polynomial commitment C = com(F), we can compute C' = com(F + G) by taking C' = C + com(G)
            * In out case, G = L_i * (v_new - v_old) 
                * where L_i is a precomputed commitment for the polynomial that equals 1 at the position we're trying to change and 0 everywhere else
                * where v_new - v_old is the vector resulting from the difference of the nodes in the path of the tree before the insertion and the nodes in the path of the tree after the insertion.
    2. Validation of data in the Verkle Tree
        - <https://dankradfeist.de/ethereum/2021/06/18/pcs-multiproofs.html>
        - In order to prove the leaf value [L]'s hash [K] points to a specific value [V], we must give [c] commitments as well as c additional KZG proofs for c nodes in the path from root to L of the form p_i = C_i(k_n) ... p_i-1 = C_i(k_n-1) where we have
            : i..k commitments C for each i'th node,
            : i..k proofs p for each i'th node,
            : m..n inputs k where k_m is the byte string in a hash of a node's value and k_m+1 is the second byte string of a node's value and so on
        - i.e. 
        we are proving that the function committed to by each of the nodes evaluates to the hash of the value of the node at k-i. For example, the first function committed to by the nodes should evaluate to the hash of the value of the node being challenged. The second function commitetted to by the nodes should evaluate to the hash of the value of the parent of the node being challenged, and so on.
        * NOTE: 
            - in the PCS-multiproofs paper, they replace the index value used for evaluation with the d-th root of unity to the power of the index which makes many operations more efficient in practice.
        
        * So what does this mean for us: [validation]
        * We will need to keep track of 
            * the prefix of each inner node and the final indexed byte of the leaf
                * will be used to raise the root of unity to replace the evaluation point of the commitment
            * i..k commitments
            * i..k proofs
            * m..n inputs

*** New Notes (before 11/25/2023) ***

What I see as the way moving forward:

1) We need a method set_commitments which will walk through all levels of the tree starting at the bottom level 40 to the root setting commitments with the verkle tree committer key and a random number generator. We will use the ark_works_polycommit PolynomialCommitment<Field, Polynomial>::commit() method which is provided in the ark_works library. This method requires a commmitter key, a labeled polynomial, and a random number generator, and I'm still trying to understand where that labeled polynomial comes from
2) when all commitments are set on the tree starting from depth d from {root..1..2..3..d-n..d-2..d-1..d} to root are set, we are able to take proofs of membership by using the get() method to first determine if the address exists in the tree. If it does, we simply need to collect the commitments from the root to the leaf and open the commitments at a point using the open() method from the ark_works library. To produce a proof of non membership, find the two leaf nodes directly next to the leaf node being searched and provide the commitments from the root to the two leaf nodes and send those to be opened and checked.
3) Finally, these openings must be checked by the ark_works_polycommit check() method.

method documentation: https://docs.rs/ark-poly-commit/latest/ark_poly_commit/trait.PolynomialCommitment.html

additional verkle tree documentation that I've been trying to use to get a better understanding of implementing the structure:
* https://www.youtube.com/watch?v=1hTscLYsaIg
* https://ethereum.org/en/roadmap/verkle-trees/#:~:text=Verkle%20trees%20(a%20portmanteau%20of,the%20ability%20to%20validate%20blocks.
* https://blog.ethereum.org/2021/12/02/verkle-tree-structure
* https://www.youtube.com/watch?v=ik7xYCTC0B4
* https://kbaiiitmk.medium.com/verkle-tree-the-verge-part-of-ethereum-9b3d59926ee9
* https://hackernoon.com/take-a-deep-dive-into-verkle-tree-for-ethereum
* https://www.youtube.com/watch?v=f7bEtX3Z57o
* https://www.youtube.com/watch?v=RGJOQHzg3UQ
* https://notes.ethereum.org/@vbuterin/verkle_tree_eip#Illustration


*** New Notes (11/25/2023) ***

Note: Proposed methods and method headers in src/lib.rs are open to modification as long as the functionality is provided and the necessary arguments from one phase are able to be passed as arguments for the next phase

Flow of the program: https://www.figma.com/file/ImdcFOgC0cZ2tcqLLat3mc/Untitled?type=whiteboard&node-id=1%3A55&t=HQibDEue6VE54kLH-1

Paragraph explanation of flowchart:

1. First, we must get the vector/list of all addresses and values that need to go into the trie. Then (1) we need to hash the addresses and transform these into nodes that will be entered into the tree. (2) We will want to keep the hashed addresses somehow in order to traverse the tree using a modified get() method to set the commitments of the tree properly described in src/lib.rs set_commitments() method. 
2. We then need to set up the universal parameters and trim them to get our prover and (1) verifier keys. I see that this is already being done in the main.rs file, but we need to ensure that we also gather the verifier key. My input to the details of the implementation of this phase in the program is outlined just above set_commitments() in src/lib.rs.
3. Next, we need to set the commitments at all of the nodes in order to prepare the root commitment which depends on all prior commitments. This will (1) involve implementing a traversal of the tree in a way that all the nodes on the bottom-most depth have their commitments set before any commitments of the depth 1 layer above the current depth have been set. It is important that all commitments at depth d be set before the commitments at depth d-1 are set. This traversal pattern will continue until the end of the tree which will be the setting of the root commitment. Note number 1 of the blocking tasks. We will need to access the randomness that was used to create the commitment in opening the commitments later on. 
4. At this point, we are now able to either begin the proof-of-membership phase or the root-proof-publication-preparation phase. (1) We will need to first ask the user whether *(5a)* they would like to test a proof-of-membership or *(5b)* simply proceed to generate the combined_proof (the root commitment) and publish it to the file. Depending on what the user proceeds to choose, we will either search for the key they are looking for and begin constructing the verkle_proof for the proof-of-membership or non-membership, or we will gather the root commitment, complete the proof construction, and publish the proof to file.

5a and 5b are just the forked decisions and can just be implemented by an if statement and taking the user input to call the correct series of methods.

*** A: The user would like to query the Verkle Trie for a proof of membership *** 
6. This will essentially necessitate the creation, opening, and checking of all commitments of each node. The details of implementation are nuanced, and I will make an effort to explain them now. In a proper verkle tree, the path would be used by the verifier in order to reconstruct the commitments alongside the sibling commitments in order to ensure that the actual commitment being checked is genuinely hiding information of the polynomial. To create this proper VerkleProof, we will need to assign three fields. The three fields are the combined_commtiment, the path, and the sibling_commitments. The combined_commitment is simply the root commitment. The path is a vector of indices which, more specifically, consists of the index of the node at each depth-level l in the tree. For this to work, all nodes in each level in the tree need to be indexed in some way. I believe that indexing based on parent/child relationships using the vector indexing of children nodes will be the best way of accomplishing this. The sibling commitments will be the vector of all of the commitments at each of the levels that was not a commitment of the path to the leaf value. The difference between the verkle-tree that we are creating and a proper verkle tree is that the verifier in a proper verkle tree will use the path in order to reconstruct the commitment being proved, but in our case, the verifier will recieve the path as a vector of commitments representing the commitments of the tree. I believe that passing the commitments rather than implementing the reconstruction of the commitment from the path in proper verkle tree fashion would serve us better in implementing the functionality. I know this is a lot of commitments, but we will need to have all of them to ensure cryptographic propogation of detecting an error in potentially malicious proofs. Our VerkleProof type will then consist of a (1) combined_commitment = root commitment, (2) path_commitments = vec<commitments> of the nodes representing the key being searched, and (3) sibling_commitments = vec<vec<commitments>> of the nodes representing the paths from root to all other leaves in the tree. If the searched-node exists, we will create a verkleproof as normal. If it does not exist, we will just do the combined_commitment and sibling_commitments composed of all leaf nodes as a proof-of-non-membership. I believe that retrieving all of these commitments should not be too difficult if we use a modified get() method that collects the commitments from all of these nodes as the method traverses all the nodes to the desired leaf node which we can query with our soon-to-be-made modified get method using the stored hash-keys from the initial insertion into the tree. This modified get() method could also serve to retrieve the randomness from the nodes which should have been completed as the blocking task #1 which we will need in order to open and check the commitments. 
7. To open the commitments, I think we should use the ark_poly_commit::PolynomialCommitment open() method for path_commitments as well as the sibling_commitments and for the combined_commitment. Refer to the notes in src/lib.rs for the specifics on what batch_open requires and how to create those necessities. 
8. To check the commitments, I think we should use the ark_poly_commit::PolynomialCommitment check() method for path_commitments as well as the sibling_commitments and for the combined commitment. Refer to the notes in src/lib.rs for the specifics on what batch_check requires and how to fulfill those parameters.

*** (B: The user would not like to query the Verkle Trie) ***
*N.B This functionality will only be useful if we can first do 6A as this functionality would only help us with Hw4 and Hw5, not Hw3*
6. In this case, we will simply have to collect the commitment from the root of the trie and open() and check() the trie's validity. In this case, there is no need for the verkle trie because the root commitment is composed using information from its children nodes, whose commitments are also composed with information from their children nodes recursively. If we can do 6A to 9, then we finish Hw3. If we can do all of this checklist, then we can get Hw4 as well if we scrap together the rest of the functionality quickly.
7. The only difference between 7a/7b is that we only need to do the open() for the combined_commitment
8. The only difference between 8a/8b is that we only need to do the check() for the combined_commitment

9. If the proof succeeds, write the combined_commitment as bytes sha256-hashed to the output file. If the proof does not succeed, then report the error.

Blocking tasks:
1. We need to add an optional randomness element to the Node struct in order to pass randomness property
2. Correct me if I'm wrong, but I think if we want data_reader.rs to be its own file, we need to have it in another folder for cargo to build it all. 

List of TODO's associated with the numbering system in the flowchart above:

Flowchart tasks:
1. Get the list of addresses and values to be properly inserted into the tree
    1. We need to hash the addresses and transform these into nodes that will be entered into the tree.
    2. We will want to keep the hashed addresses in order to traverse the tree later on.
2. Fix the universal param setup and trim
    1. Store verifer key
3. Set the commitments of the tree
    All of the following iterators are not necessarily part of this phase, but moving forward, we will need to be able to iterate over these collections, so I believe this was an appropriate place to put them.
    1. Implement an iterator for vec<ark_poly_commit::PolynomialCommitment::Polynomials>
    2. Implement an iterator for vec<ark_poly_commit::PolynomialCommitment::LabeledPolynomials> 
    3. Implement an iterator for vec<ark_poly_commit::PolynomialCommitment::Commitments>
    4. Implement an iterator for vec<ark_poly_commit::PolynomialCommitment::LabeledCommitments> 
    5. Implement an iterator for vec<vec<ark_poly_commit::PolynomialCommitment::Commitments>>
    6. Implement an iterator for vec<vec<ark_poly_commit::PolynomialCommitment::LabeledCommitments>>
    7. Implement an iterator for vec<Randomness>
    8. Implement an iterator for vec<vec<Randomness>>
    9. Implement a modified_get() method which will use the stored hash-keys to access all nodes in the tree in the pattern described above in Paragraph_Explanation_of_Chart #3. It would serve us well to implement this with 
        a. implement set_commitments() to use modified_get() traversal of the tree in a way that all the nodes on the bottom-most depth have their commitments set before any commitments of the depth 1 layer above the current depth have been set
4. Proof-of-membership or just publish to file
    1. Query the user to either enter a *5a* key or enter a *5b* special character to just move on to combined_commitment publication
    N.B. We should focus on implementing *A* functionality at first rather than *B* functionality. Refer to the N.B. on 6b above.
5a and 5b can be implemented with an if statement which takes the user's input and executes the correct series of methods.

*** A ***

6. Create VerkleProof
    1. collect combined_commitment as the root commitment
    2. get() the node. If it exists, we will create a verkleproof as normal. If it does not exist, we will just do the combined_commitment and sibling_commitments composed of all leaf nodes as a proof-of-non-membership.
    3. if the searched-for node exists, modified_get() the leaf node the user wants to look for and create a proof of it 
    4. modified_get() all other leaf nodes in the tree that weren't collected in the path_commitment collection phase and assign the sibling_commitments to it.
Note: For the actual implementation of opening and checking, I'm thinking that it may be easier to implement these steps all in one method within the proof-of-membership() method just to make argument passing easier so that we don't have to package all three proofs into another struct or something to move them accross with the challenge_generator and point.
7. Open the VerkleProof
    1. Refer to these docs on open(): https://docs.rs/ark-poly-commit/latest/ark_poly_commit/trait.PolynomialCommitment.html#tymethod.open
    2. Refer to my notes in src/lib.rs. They are the same parameters as batch_open other than points rather than query_set which just means we don't need to make a BTreeSet for the random evaluation points, but just a single evaluation point. I looked into the methods more, and I think we can get the same functionality for the project using open() rather than batch_open().
    Note: We will need to open() the commitments of the combined_commitment, all the commitments of the vector path_commitment if this is a proof-of-membership, and all the commitments of the vector of vectors sibling_commitment. Also note that we will need to provide the proper randomness, vector of randomness, and vector of vectors of randomness, respectively, to the above commitments being opened. This means that the output of this phase will be 3 proofs if we create our iterator properly for the vector of commitments and vector of vector of commitments for use in opening and checking.
8. Check the VerkleProof
    1. Refer to these docs on check(): https://docs.rs/ark-poly-commit/latest/ark_poly_commit/trait.PolynomialCommitment.html#tymethod.check
    2. Refer to my notes in src/lib.rs. They are the same parameters as batch_check() other than points instead of query_set which just means we don't need to make a BTreeSet for the random evaluation points, but just a single evaluation point. The other difference is values instead of evaluations which just a vector of the values corresponding with I looked into the methods more, and I think we can get the same functionality for the project using open() rather than batch_open().
    Note: We will be recieving at most 3 proofs (proof of membership) or 2 proofs (proof-of-nonmembership) which all need to be validated in order for the proof to be completed and valid.
    3. Notify the user of the validity or non-validity of the proof
9. Hash the combined_commitment and publish it to a file

*** B ***
*N.B. More details to come if we can actually finish the above* 
6. The same but only root commitment

7. The same but only root commitment 

8. The same but only root commitment

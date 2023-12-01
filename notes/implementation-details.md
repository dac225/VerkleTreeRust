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

*** New Notes ***

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


            


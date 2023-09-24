Requirements of a Trie:
    - Definition:
        - A trie is a tree-like data structure wherein the nodes of the tree store the entire binary/hexadecimal alphabet, and [bit-strings] can be re[trie]ved by traversing down a branch path of the tree.
    - Node structure:
        - a set of linked nodes, all connecting back to an empty root node
            -  each node contains an array of pointers to child nodes, one for each possible hexadecimal value
        - NOTE: the size of a trie is directly connected/correlated to the size of the 
        alphabet that is being represented
            - in our case this is size=16 for each of the hexadecimal values, but recall that Kuszmaul's research suggests that a branching factor of 32 provides a speedup factor of 5 compared to a merkle tree. We can achieve a branching factor of 32 taking the first 5 bits from a hash of a node to use as the index
            on which we will sort the children
            branch #/index i, binary character/rust reference r_i
                    0  0_0000  
                    1  0_0001 
                    2  0_0010  
                    3  0_0011  
                    4  0_0100  
                    5  0_0101  
                    6  0_0110  
                    7  0_0111  
                    8  0_1000  
                    9  0_1001  
                    10 0_1010  
                    11 0_1011    
                    12 0_1100  
                    13 0_1101  
                    14 0_1110   
                    15 0_1111  
                    16 1_0000  
                    17 1_0001  
                    18 1_0010  
                    19 1_0011  
                    20 1_0100  
                    21 1_0101  
                    22 1_0110  
                    23 1_0111  
                    24 1_1000  
                    25 1_1001  
                    26 1_1010  
                    27 1_1011
                    28 1_1100
                    29 1_1101
                    30 1_1110
                    31 1_1111   
        - what is in a single node of a trie?
            - both the value and the references to other nodes could be empty
            * Each node contains an array A of rust references (pointers) r_i for i branches. The 5-bit index string contained at index i is defined by the reference's index in its child node's array *
            - Summary: A single node in a trie contains just
                1) A value which might be null
                2) An array of references to child nodes, all of which also might be null
        - the set of 5-bit strings created when dividing the hash of a node's value is the set of keys that we will use to traverse down the tree. The value at any given node will be placed at the leaf node of the path traced from this traversal

Requirements of a Verkle trie structure:
    - What is included in each of the nodes?
        - the hash
        - the commitment
        - the list of 32 references/pointers
    - A trie where (d = branching factor/max # of children)
        - inner nodes are...
            - d-ary vector commits to their children where the i-th child
            contains all nodes with the prefix i as the d-digit binary number
            * The root of a leaf node is simply a hash of the (key, value) pair of 32 byte
            strings whereas the root of an inner node is the hash of the vector commitment 
            (in KZG, this is a G_1(group element in a finite field) element) *
    - Proofs:
        - <https://dankradfeist.de/ethereum/2021/06/18/pcs-multiproofs.html>
        - In order to prove the leaf value [L]'s hash [K] points to a specific value [V], we must give [c] commitments as well as c additional KZG proofs for c nodes in the path from root to L of the form p_i = C_i(k_n) ... p_i-1 = C_i(k_n-1) where we have
            : i..k commitments C for each i'th node,
            : i..k proofs p for each i'th node,
            : m..n inputs k where k_m is the first 5-bit string in a hash of a node's value and k_m+1 is the second 5-bit string of a node's value and so on
        - i.e. 
        we are proving that the function committed to by each of the nodes evaluates to the hash of the value of the node at k-i. For example, the first function committed to by the nodes should evaluate to the hash of the value of the node being challenged. The second function commitetted to by the nodes should evaluate to the hash of the value of the parent of the node being challenged, and so on.
        * NOTE: 
            - in the PCS-multiproofs paper, they replace the index value used for evaluation with the d-th root of unity to the power of the index which makes many operations more efficient in practice.
    - Inserting into the trie:
        - first check to make sure that value doesn't already exist
        - walk down the trie from root every 5 bits of the hash of the value being added to the trie. At every level, we check if there is a null pointer for the 5-bit string corresponding with each level of the tree. If the pointer is null, we create a new node which will contain a reference to a node
        

Understanding Rust Modules and Traits:
    - Traits allow us to define a set of methods to be used by multiple types
        - Traits are not typically implemented inside the trait definition, rather defined
        in separate [impl] blocks to allow method overloading
        - there are default implementations as well (as long as it says that in the documentation)
    - References to implementations of methods stored in traits can also be used as function parameters 

        
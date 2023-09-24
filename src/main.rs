use VerkleTreeRust::hash;

fn main() {
    let data = b"Hello, world!";
    let hashed_data = hash(data);
    println!("Hashed data: {:?}", hashed_data);
}
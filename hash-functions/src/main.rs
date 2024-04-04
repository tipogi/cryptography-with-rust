pub mod algorithms;

use algorithms::sha2_algo::hash2_encryption_algorithm;
use algorithms::sha3_algo::hash3_encryption_algorithm;

fn main() {
    hash2_encryption_algorithm();
    hash3_encryption_algorithm();
}

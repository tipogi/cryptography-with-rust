# Hash function exercises

- [x] Use the `sha2` crate to implement a hash function that uses the SHA-2-256 algorithm. 
- [x] Use the `sha3` crate to implement a hash function that uses the SHA-3-256 algorithm. 
- [ ] Start by converting the string to bytes and then applying a simple mathematical operation like XOR or addition to each byte. You can also apply a bitwise rotation or shift operation to add some randomness to the output.
- [ ] Try implementing a complete hash function that takes an input message and returns a SHA-256 hash value.
- [ ] Implement a hash function using a custom round function: Custom round function should take a state value and a message block as input and produce a new state value as output. You can use bitwise operations, mathematical operations, and rotations to create a complex and secure round function.
- [ ] Implement a keyed hash function: Write a keyed hash function that takes a secret key and a message as input and produces a hash value as output. This type of hash function is called a __HMAC__ (Hash-based Message Authentication Code) and is commonly used for message authentication and data integrity
- [ ] Data Integrity Verification: Implement a simple data integrity verification system using a hash function. Generate a hash of a file or message and verify its integrity by comparing the hash with the recalculated hash.

- [ ] Implement a hash table: Implement collision resolution techniques, such as chaining or open addressing, to handle collisions

- [ ] Merkle Tree: Implement a Merkle tree using a hash function. A Merkle tree is a binary tree structure that allows efficient verification of the integrity and consistency of large datasets.Understand how hash functions can be used in data structures for efficient verification.



`NOTE: cmd+shift+v to preview in VSCode`
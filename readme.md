# Cryptography with Rust

`The best way to understand something is practicing`

The aim of this repository is to get a better knowledge of the cryptography. For that, it will separete in different subfolders the content that might be interesting.

- __hash functions__: Use _symmetric cryptography_ to get fixed number of characters
- __password-hashing__: Turn a password into cyphertext
- __identity__: Identity creation, not trusting any third party

## Commands

```bash
cargo watch -x "run -p workspace_name"
cargo watch -x "test -p workspace_name"
# Active stdout to print the outputs of println!
cargo watch -x "test -p workspace_name -- --nocapture"
```
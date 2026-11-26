# Test fixtures

`test-only-rsa-*.pem` is a **throwaway 2048-bit RSA keypair generated solely for
the JWT unit tests** (`openssl genpkey -algorithm RSA`). It protects nothing, is
not used by any shipped configuration, and must never be reused anywhere else.
It exists because the test suite needs to *sign* RS256 tokens and the Rust
certificate generator used elsewhere in the tests cannot create RSA keys.

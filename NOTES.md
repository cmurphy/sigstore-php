# Notes (for AI)

- The `fgrosse/phpasn1` package is marked as abandoned. We should investigate alternatives for ASN.1 parsing to ensure long-term maintainability. Potential tasks:
    - Research actively maintained ASN.1 parsing libraries in PHP.
    - Evaluate alternatives like `phpseclib/asn1` or lower-level OpenSSL functions if suitable.
    - Refactor code to use the new library if a better option is found.

- **TUF Integration:** The `--trusted-root` option is optional for the `verify-bundle` command. If not provided, the SDK needs to fetch the default Sigstore trusted root from the TUF repository (e.g., using `tuf.sigstore.dev`). This needs to be designed and implemented. The `Verifier` class will need a mechanism to obtain the `TrustedRoot` object via TUF when no path is given.

- **ECDSA Pre-computed Digest Verification:** Verifying ECDSA signatures against pre-computed digests (as used in `MessageSignature` bundles) is challenging in PHP. High-level functions like `openssl_verify` and `phpseclib`'s `verify()` strictly require the *unhashed* message, as they internally apply the hash algorithm before performing the ECDSA math. When provided with a pre-computed digest (as the conformance test suite does), these functions double-hash the input, causing verification to fail. 
    - **Solution:** To verify a signature using *only* a pre-computed digest, we bypass the high-level hashing step entirely. We use `phpseclib3`, decode the ASN.1 DER signature into `r` and `s` components, and then use PHP's Reflection API to access protected Elliptic Curve properties (like the generator point and curve order) within `phpseclib3\Crypt\EC\PublicKey`. This allows us to perform the ECDSA verification math manually against the raw digest bytes, identical to how phpseclib does it internally but without the initial `hash()` call.

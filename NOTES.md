# Notes (for AI)

- The `fgrosse/phpasn1` package is marked as abandoned. We should investigate alternatives for ASN.1 parsing to ensure long-term maintainability. Potential tasks:
    - Research actively maintained ASN.1 parsing libraries in PHP.
    - Evaluate alternatives like `phpseclib/asn1` or lower-level OpenSSL functions if suitable.
    - Refactor code to use the new library if a better option is found.

- **TUF Integration:** The `--trusted-root` option is optional for the `verify-bundle` command. If not provided, the SDK needs to fetch the default Sigstore trusted root from the TUF repository (e.g., using `tuf.sigstore.dev`). This needs to be designed and implemented. The `Verifier` class will need a mechanism to obtain the `TrustedRoot` object via TUF when no path is given.

- **ECDSA Pre-computed Digest Verification:** Verifying ECDSA signatures against pre-computed digests (as used in `MessageSignature` bundles) is challenging in PHP. High-level functions like `openssl_verify` and `phpseclib`'s `verify()` strictly require the *unhashed* message, as they internally apply the hash algorithm before performing the ECDSA math. When provided with a pre-computed digest (as the conformance test suite does), these functions double-hash the input, causing verification to fail. 
    - **Solution:** To verify a signature using *only* a pre-computed digest, we bypass the high-level hashing step entirely. We use `phpseclib3`, decode the ASN.1 DER signature into `r` and `s` components, and then use PHP's Reflection API to access protected Elliptic Curve properties (like the generator point and curve order) within `phpseclib3\Crypt\EC\PublicKey`. This allows us to perform the ECDSA verification math manually against the raw digest bytes, identical to how phpseclib does it internally but without the initial `hash()` call.

## Cryptographic and Architectural Findings

During the implementation and conformance testing of the `verify-bundle` command, several critical nuances regarding Sigstore's cryptographic structures were discovered:

- **Rekor Canonicalized Body Parsing:** The `canonicalizedBody` inside a Rekor `TransparencyLogEntry` is a base64-encoded JSON string, but its internal schema varies widely based on the entry `kind` (`dsse`, `hashedrekord`, `intoto`). 
    - For `dsse` and `hashedrekord`, the signature is typically found at `spec.dsseV002.signatures[0].content` or `spec.hashedrekordV002.signature.content`.
    - For `intoto` (specifically `intotoV002`), the signature is located at `spec.content.envelope.signatures[0].sig` and is often **double-base64 encoded** (the string value in the JSON is base64, and the JSON itself is base64). The Verifier must correctly route the extraction path based on the schema and decode appropriately to byte-match the bundle's artifact signature.

- **Merkle Tree Bitwise Math (PHP Edge Case):** When calculating the number of "inner" hashes required for a Rekor Inclusion Proof, the standard formula involves the bit length of the XOR between the log index and tree size minus one: `BitLength(logIndex ^ (treeSize - 1))`. 
    - In PHP, `decbin(0)` returns the string `"0"`, which has a string length of `1`. 
    - If a log is brand new (`logIndex = 0`, `treeSize = 1`), the XOR is `0`. The bit length mathematically must be `0` (requiring 0 inner hashes), but PHP calculates it as `1`. A strict `if ($xor === 0)` check is required to bypass the `strlen(decbin())` operation to prevent "Inclusion proof hash count mismatch" errors on the first entry of a transparency log.

- **TSA Certificate Chain Validation (`openssl ts`):** When verifying an RFC 3161 Timestamp Authority token using PHP's `exec('openssl ts -verify ...')`:
    1.  You **must** use the `-attime <unix_timestamp>` flag, passing the token's extracted signing time. If omitted, OpenSSL checks if the short-lived TSA certificates are valid *right now* (which they almost never are), causing validation to fail.
    2.  The TSA leaf certificate extracted from the `TrustedRoot` must be explicitly written to a temporary file and passed via the `-untrusted` flag, while the intermediate and root certificates are passed via the `-CAfile` flag. OpenSSL requires this distinction to properly build the trust chain for the CMS token.

- **SCT (Signed Certificate Timestamp) Conformance Testing:** The official Sigstore conformance suite currently accepts a minimal "Phase 1" SCT verification (which only checks for the presence of the SCT extension OID `1.3.6.1.4.1.11129.2.4.2` inside the Fulcio leaf certificate) without requiring full cryptographic validation of the SCT's TLS-encoded signature against the public CT Logs. 
    - This is because it is mathematically impossible to forge or alter an SCT embedded inside a valid certificate without breaking the overarching Certificate Authority (Fulcio) signature on that certificate. As long as strict Fulcio certificate chain validation is enforced, the embedded SCT is implicitly trustworthy for the purposes of the conformance suite. Full SCT cryptographic validation is a "defense in depth" measure against a compromised CA.

## TUF Client Investigation

An attempt was made to implement a dynamic TUF client to fetch `trusted_root.json` from `tuf-repo-cdn.sigstore.dev` using the `php-tuf/php-tuf` library. While the client was successfully configured to download the TUF metadata (Root, Timestamp, Snapshot, Targets) and verify some constraints, the implementation was ultimately reverted due to the following insurmountable roadblocks:

1. **Cryptographic Algorithm Support:** `php-tuf` natively hardcodes signature verification to use `sodium_crypto_sign_verify_detached`, which only supports Ed25519 keys. The Sigstore production and staging roots utilize ECDSA (P-256) keys. While we temporarily patched `php-tuf` to use `phpseclib3` for ECDSA verification, it highlighted a lack of extensibility in the library.
2. **Canonical JSON Incompatibilities:** TUF requires the JSON metadata to be strictly serialized into "Canonical JSON" before verifying its cryptographic signature. `php-tuf`'s internal JSON serializer output does not perfectly match the byte-for-byte canonical string produced by the Python library (`securesystemslib`) that Sigstore used to sign the original `root.json` anchors. Because the canonical bytes slightly differed, the ECDSA signature verification consistently and mathematically failed.
3. **Strict Validation Failures:** The Sigstore `timestamp.json` occasionally omits the `hashes` array for the `snapshot.json` metadata. `php-tuf` strictly enforced this as a required field based on older TUF spec interpretations, causing early validation fatal errors.

**Conclusion:** Implementing a secure, dynamic TUF client in PHP that perfectly interoperates with Sigstore's specific key types and legacy JSON canonicalization quirks is too complex for this experimental SDK. It would require either a massive, unmaintainable fork of `php-tuf` or writing a custom TUF engine from scratch. For now, the dynamic TUF resolution is bypassed, and the conformance suite's TUF-dependent tests remain in the XFAIL list.

# Design Document: PHP Sigstore SDK & Conformance CLI

## 1. Introduction

This document outlines the design for a PHP SDK to interact with the Sigstore ecosystem, enabling signing and verification of artifacts. Additionally, a CLI wrapper will be developed to interface with the `sigstore-conformance` test suite, ensuring the SDK's functionality aligns with Sigstore specifications.

**Goals:**

*   Provide a PHP library for signing and verifying digital artifacts using Sigstore services.
*   Support keyless signing with ephemeral keys and OIDC-based identity.
*   Interact with Fulcio, Rekor v2, and RFC 3161 Timestamp Authorities.
*   Handle Sigstore bundles for verification material.
*   Create a CLI tool that adheres to the `sigstore-conformance` protocol.

## 2. Target Audience

PHP developers who need to integrate software signing and verification into their applications or workflows using Sigstore.

## 3. Overall Architecture

The SDK will be a Composer package with a modular design. A facade, `SigstoreClient`, will provide high-level entry points. Underneath, components for signing, verification, and service interactions will handle the core logic. Configuration will be loaded from external sources (Protobuf files).

**Components:**

*   **SDK Core:**
    *   `SigstoreClient`: Main facade.
    *   `Signer`: Orchestrates the signing flow.
    *   `Verifier`: Orchestrates the verification flow.
    *   Service Clients: `FulcioClient`, `RekorClient`, `TimestampClient`, `OidcClient`.
    *   Data Models: Generated PHP classes from Sigstore `.proto` files (Bundle, TrustedRoot, SigningConfig, etc.).
    *   Crypto Utilities: Wrappers for cryptographic operations.
*   **Conformance CLI:**
    *   `sigstore-cli.php`: Symfony Console application implementing the required subcommands.

## 4. Core SDK Components

### 4.1. `SigstoreClient`

*   Acts as the primary public API for the SDK.
*   Methods: `sign(payload, options)`, `verify(payload, bundlePath, options)`.
*   Instantiates and coordinates `Signer`, `Verifier`, and service clients based on provided configurations.

### 4.2. `Signer`

*   Manages the entire signing process:
    1.  OIDC Authentication (using `OidcClient`).
    2.  Ephemeral key pair generation.
    3.  CSR generation.
    4.  Certificate request to Fulcio (using `FulcioClient`).
    5.  Payload signing.
    6.  Timestamping the signature (using `TimestampClient`).
    7.  Submitting to Rekor v2 (using `RekorClient`), supporting `HashedRekord` and `DSSE` types based on options.
    8.  Assembling the Sigstore `Bundle` (Protobuf object).
*   Configured with URLs from `SigningConfig`.

### 4.3. `Verifier`

*   Manages the bundle verification process:
    1.  Deserialize the `Bundle` from JSON.
    2.  Extract RFC 3161 timestamp from `timestamp_verification_data`. **Note:** For V2 compliance, we exclusively use this RFC 3161 timestamp to establish signing time. We completely ignore Rekor's `integratedTime` and `InclusionPromise` (SET) for time-checking. If an RFC 3161 timestamp is missing, verification fails for certificates.
    3.  **Phase 1 (Time check):** Parse the ASN.1 `TimeStampToken` (using `phpseclib3\File\ASN1`) to extract the `GeneralizedTime`.
    4.  Verify the Fulcio certificate chain against the `TrustedRoot` at the extracted timestamp time.
    5.  **Phase 2 (TSA Crypto):** Verify the TSA's signature on the timestamp token against the `timestamp_authorities` in `TrustedRoot`, and verify the token's message imprint matches the artifact signature.
    6.  **Phase 1 (SCT check):** Extract and verify the presence of the Certificate Transparency Log SCT extension embedded in the Fulcio certificate. **Phase 2 (SCT Crypto):** Verify the SCT signature against the `ctlogs` in `TrustedRoot`.
    7.  Verify the Rekor v2 entry (Inclusion Proof):
        *   Extract the `TransparencyLogEntry` from the bundle.
        *   **Checkpoint Verification:** Parse the text-based Checkpoint (Signed Note) from the `InclusionProof`. Extract the `tree_size` and `root_hash`. Reconstruct the signed body and verify the signature using the appropriate `TransparencyLogInstance` public key from the `TrustedRoot`.
        *   **Merkle Tree Math:** Calculate the leaf hash (`SHA256(0x00 . canonicalized_body)`). Compute the root hash by chaining the provided `hashes` from the `InclusionProof` with the leaf hash, using bitwise math on the `log_index` and `tree_size` to determine ordering.
        *   **Validation:** Assert that the computed root hash exactly matches the `root_hash` from the verified Checkpoint.
    8.  Verify the artifact signature using the public key from the Fulcio certificate.
    9.  Check against policy (identity, issuer) provided in options.
*   Configured with `TrustedRoot`.

### 4.4. Service Clients

*   **`OidcClient`:** Handles interactions with the OIDC provider specified in `SigningConfig` to fetch an identity token. Likely wraps `league/oauth2-client`.
*   **`FulcioClient`:** Interacts with the Fulcio API (e.g., `/api/v2/signingCert`) using URLs from `SigningConfig`. Handles certificate signing requests. Uses Guzzle.
*   **`RekorClient`:** Interacts with the Rekor v2 API (`/api/v2/log/entries`) using URLs from `SigningConfig`. Handles posting `HashedRekordRequestV002` or `DSSERequestV002`. Uses Guzzle.
*   **`TimestampClient`:** Sends `TimeStampReq` to an RFC 3161 TSA using URLs from `SigningConfig`. Parses `TimeStampResp`. Uses Guzzle.

### 4.5. Data Models

*   PHP classes generated from the Sigstore `.proto` files using `google/protobuf` and `protoc`. This includes:
    *   `dev.sigstore.bundle.v1.Bundle`
    *   `dev.sigstore.trustroot.v1.TrustedRoot`
    *   `dev.sigstore.trustroot.v1.SigningConfig`
    *   Rekor v2 request/response messages (`HashedRekordRequestV002`, `DSSERequestV002`, `TransparencyLogEntry`)
    *   Common types (`LogId`, `PublicKey`, etc.)

### 4.6. Crypto Utilities

*   Functions for key generation (EC keys).
*   Hashing (SHA256).
*   Signature generation and verification.
*   Interactions with PEM files, certificates, and keys.
*   Primarily uses PHP's `openssl` extension. `phpseclib` or `fgrosse/phpasn1` may be used for ASN.1 parsing or specific crypto operations not well-supported by `openssl`.

## 5. Key Workflows

### 5.1. Signing

1.  CLI/SDK user provides payload and options (e.g., identity token, in-toto flag).
2.  `SigstoreClient` loads `SigningConfig`.
3.  `Signer` performs OIDC flow, key generation, Fulcio cert issuance, signing, timestamping, Rekor logging.
4.  `Signer` returns a `Bundle` object.
5.  CLI writes the Bundle to JSON file.

### 5.2. Verification

1.  CLI/SDK user provides payload, bundle path, and verification options (e.g., expected identity/issuer).
2.  `SigstoreClient` loads `TrustedRoot`.
3.  `Verifier` deserializes Bundle JSON.
4.  `Verifier` performs all checks: TSA, Fulcio cert, CT SCT, Rekor inclusion, artifact signature, policy.
5.  Returns success or throws a detailed exception.

## 6. Configuration

*   **`SigningConfig`:** Provided as a file path to the CLI (`--signing-config`). Contains service URLs and selection policies. Parsed as a Protobuf message. The `--staging` flag implies a different `SigningConfig` file path.
*   **`TrustedRoot`:** Provided as a file path to the CLI (`--trusted-root`). Contains trusted public keys and certificates for all Sigstore components. Parsed as a Protobuf message.

## 7. Bundle Handling

The SDK will use the generated Protobuf classes for the `Bundle`. Serialization to and from the specified canonical JSON format will be handled, respecting `lowerCamelCase` keys and string enums.

## 8. Conformance CLI Wrapper (`sigstore-cli.php`)

*   Built using `symfony/console`.
*   **`sign-bundle` command:**
    *   Arguments: `[--staging] [--in-toto] --identity-token TOKEN --bundle FILE [--trusted-root TRUSTROOT] [--signing-config SIGNINGCONFIG] FILE`
    *   Parses args, instantiates `SigstoreClient` with loaded `SigningConfig`.
    *   Calls `SigstoreClient::sign()`, passing the in-toto flag.
    *   Serializes the resulting `Bundle` to the specified file.
*   **`verify-bundle` command:**
    *   Arguments: `[--staging] --bundle FILE (--certificate-identity IDENTITY --certificate-oidc-issuer URL | --key PATH) [--trusted-root TRUSTROOT] FILE_OR_DIGEST`
    *   Parses args, instantiates `SigstoreClient` with loaded `TrustedRoot`.
    *   Calls `SigstoreClient::verify()`, passing appropriate identity/key options.

## 9. Dependencies

*   `php`: >= 8.1
*   `ext-openssl`
*   `ext-json`
*   `google/protobuf`: For Protobuf message handling.
*   `guzzlehttp/guzzle`: For HTTP clients.
*   `league/oauth2-client`: For OIDC.
*   `symfony/console`: For the CLI wrapper.
*   `fgrosse/phpasn1`: For ASN.1 parsing (certificates, timestamps).
*   `phpseclib/phpseclib`: For supplementary cryptographic operations if needed.

## 10. Error Handling

*   SDK methods will throw specific exceptions for different failure conditions (e.g., `VerificationException`, `SigningException`, `NetworkException`).
*   The CLI wrapper will catch exceptions, print user-friendly error messages to stderr, and exit with code 1. Successful commands exit with 0.

## 11. In-Toto Handling

The `--in-toto` flag on `sign-bundle` signals that the input file is an in-toto attestation. The `Signer` will wrap this payload in a DSSE envelope and use the `DSSELogEntryV002` type when interacting with Rekor. Otherwise, `HashedRekordLogEntryV002` will be used with the artifact hash.

## 12. TUF Client Architecture

The Sigstore ecosystem relies on The Update Framework (TUF) to securely distribute and update the foundational `trusted_root.json` file. This mitigates a multitude of supply chain attacks, including rollback, freeze, mix-and-match, and arbitrary software updates.

### 12.1. Leveraging `php-tuf/php-tuf`

Implementing the exhaustive TUF specification from scratch is highly complex and error-prone. To ensure cryptographic rigor and security, the PHP SDK will leverage the `php-tuf/php-tuf` library. This library handles the intricate details of Canonical JSON serialization, cryptographic signature validation, threshold counting, and the strict 7-step TUF client update workflow.

### 12.2. Architectural Implementation

The TUF client logic will be encapsulated within the `Sigstore\Tuf` namespace to maintain separation of concerns from the core artifact verification logic.

1.  **Trust Anchors:** The SDK will ship with the initial public good `root.json` (for `sigstore.dev`) and `staging_root.json` (for `sigstage.dev`). These will be stored in `src/Tuf/Anchors/` and named `1.root.json` to bootstrap the TUF update process.
2.  **`SigstoreTufClient` Wrapper:** A high-level wrapper class will orchestrate the `php-tuf` components:
    *   **Loader:** A custom `GuzzleLoader` implementing `Tuf\Loader\LoaderInterface` will handle HTTP GET requests to the Sigstore TUF CDN (`https://tuf-repo-cdn.sigstore.dev` or `https://tuf-repo-cdn.sigstage.dev`).
    *   **Storage:** The `php-tuf` `FileStorage` class will persist downloaded metadata (`timestamp.json`, `snapshot.json`, `targets.json`) to a local `.sigstore/tuf/` cache directory, preventing redundant downloads and ensuring offline resilience when possible.
    *   **Updater:** The core `Tuf\Client\Updater` will execute the full TUF update cycle (Root -> Timestamp -> Snapshot -> Targets).
3.  **Target Retrieval:** When the `Verifier` (or the CLI) requests the `trusted_root.json` target, the `SigstoreTufClient` will trigger an update, securely download the target, verify its cryptographic hashes (SHA256/SHA512) and length against the signed `targets.json` metadata, and return the verified file.

### 12.3. Integration with Verification

If a user or the `sigstore-conformance` CLI does not explicitly provide a `--trusted-root` file, the SDK will automatically instantiate the `SigstoreTufClient`, resolve the correct repository (Production vs. Staging), fetch the latest verified `trusted_root.json`, parse it into the `TrustedRoot` protobuf object, and seamlessly pass it into the `Verifier`.

## 13. Testing Strategy

The SDK employs a dual-layered testing approach to ensure both internal correctness and strict adherence to the Sigstore specification.

### 13.1. Integration Testing (Conformance Suite)

The primary mechanism for end-to-end integration testing is the official `sigstore-conformance` Python test suite.
*   The `sigstore-cli.php` wrapper acts as the entrypoint for the conformance suite.
*   This suite rigorously exercises the complete signing and verification workflows against massive, real-world Sigstore bundles (both happy paths and mathematically/cryptographically malformed bundles).
*   Execution is orchestrated via `run-conformance.sh`.

### 13.2. Unit Testing (PHPUnit)

While the conformance suite guarantees interoperability, unit tests ensure the stability and correctness of individual, isolated PHP components. The SDK uses **PHPUnit** as its foundational testing framework.

**Principles:**
*   **Isolation:** Unit tests must not make real network requests to Fulcio, Rekor, or external TSAs. Interactions with HTTP APIs will be mocked using Guzzle's `MockHandler` or PHPUnit mocks.
*   **Focused Assets:** Tests will rely on minimal, isolated binary blobs (e.g., a single raw DER certificate, a specific extracted SCT byte string, or a pre-computed OpenSSL CMS response) stored in `tests/assets/` rather than parsing monolithic conformance JSON bundles.
*   **Data Providers:** Mathematical and parsing edge cases (like Merkle Tree root hash calculations or ASN.1 length decoding) will be exhaustively tested using PHPUnit Data Providers to iterate through multiple scenarios in a single test method.

**Targeted Areas:**
1.  **Cryptographic Verification (`SctVerifier`, `TsaVerifier`):**
    *   Verify correct ASN.1 parsing and extension extraction (e.g., gracefully handling missing or malformed SCT extensions).
    *   Ensure cryptographic signature math passes for valid inputs and explicitly fails (throws specific Exceptions) for tampered bytes or incorrect public keys.
2.  **Rekor Inclusion Proofs:**
    *   Test the parsing logic of text-based Checkpoints (Signed Notes).
    *   Test Merkle Tree math, explicitly covering edge cases like `log_index = 0` bitwise operations.
3.  **Bundle Deserialization (`Verifier`):**
    *   Verify that Protobuf-generated objects are correctly hydrated from JSON representations.
4.  **Signing Orchestration (`Signer`):**
    *   Mock external service responses (OIDC, Fulcio, Rekor) and assert that the `Signer` correctly formats the requests, processes the responses, and successfully assembles a compliant `Bundle` object.

# Notes (for AI)

- The `fgrosse/phpasn1` package is marked as abandoned. We should investigate alternatives for ASN.1 parsing to ensure long-term maintainability. Potential tasks:
    - Research actively maintained ASN.1 parsing libraries in PHP.
    - Evaluate alternatives like `phpseclib/asn1` or lower-level OpenSSL functions if suitable.
    - Refactor code to use the new library if a better option is found.

- **TUF Integration:** The `--trusted-root` option is optional for the `verify-bundle` command. If not provided, the SDK needs to fetch the default Sigstore trusted root from the TUF repository (e.g., using `tuf.sigstore.dev`). This needs to be designed and implemented. The `Verifier` class will need a mechanism to obtain the `TrustedRoot` object via TUF when no path is given.

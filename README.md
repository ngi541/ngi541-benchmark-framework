# NGI541 NGINX QUIC Integration

Experimental integration of the NGI541 cryptographic execution engine
with NGINX QUIC/HTTP/3 packet protection.

## Validated baseline

- NGINX: 1.31.6
- OpenSSL: 3.5.9
- NGI541: 0.1.1
- NGI541 API: prepared-key public API
- NGINX TLS/HKDF: OpenSSL
- QUIC AES-GCM packet protection: NGI541
- QUIC AES header protection: NGI541 AES-CTR
- ChaCha20/other unsupported suites: OpenSSL fallback
- QUIC Retry integrity protection: OpenSSL

## NGI541 QUIC path

For AES cipher suites:

TX:

    plaintext
      -> NGI541 prepared AES-GCM
      -> ciphertext + authentication tag
      -> NGI541 prepared AES-CTR header protection

RX:

    protected packet
      -> NGI541 prepared AES-CTR header unprotection
      -> packet number / nonce
      -> NGI541 prepared AES-GCM authentication + decryption

OpenSSL remains responsible for TLS 1.3, X.509 and HKDF.

## Functional validation

Validated with the pinned nginx-tests revision:

- `quic_ciphers.t`: PASS
- `h3_headers.t`: PASS
- `quic_key_update.t`: PASS
- NGI541 corrupted authentication-tag test: PASS
- complete `h3_*.t + quic_*.t` suite:
  - Files: 24
  - Tests: 331
  - Failures: 0

No performance claims are part of this validation.

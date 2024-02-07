# zktls
Repository for development of the TLS 1.2 and TLS 1.3 stacks in Noir, to produce ZKPs that can be published to the blockchain

The objective is to make it possible to prove and authenticate connections to web servers, in order to then publish such proofs to the blockchain as oracles. This approach is similar to zkEmail (https://blog.aayushg.com/zkemail/), which brings new possibilities for blockchain dApps that are baffling and endless (https://speakerdeck.com/sorasuegami/ethcon-korea-2023-zk-email-on-chain-verification-of-emails-using-zkp?slide=34), and we aim to extend it to enable users to prove not just data that servers are willing to send them by email, but that can be found simply on any normal web server.
## TLS version
A quick google search reveals that amongst the top web servers support for TLS 1.3 is at 63% (https://www.f5.com/labs/articles/threat-intelligence/the-2021-tls-telemetry-report) and support for TLS 1.2 is at 95% (https://www.clickssl.net/blog/ssl-statistics). For this reason it might be wiser to first implement support for TLS 1.2, in order to have access to proofs of connections from a broader range of popular websites, or one could also implement TLS 1.3 first and save development time on deprecated cipher suites, at the cost of reduced (but still significant for serious use-cases) access to proofs of connection to popular websites.

## TLS 1.2
REF: https://datatracker.ietf.org/doc/html/rfc5246#autoid-58

the TLS protocol contains a large quantity of states and state transitions that need to be coded up. This is by itself not a small task, but we can make it easier if we first focus on implementing all the required primitives, and then focus on implementing the protocol code. As a further note: we need not implement protocol code for the server, as it is unlikely to be particularly useful for the use-cases we envision in zkTLS.

These are the building blocks we need:
- Compression
- PRF
- MAC:
  - [ ] HMAC_MD5
  - [ ] HMAC_SHA1
  - [ ] HMAC_SHA256
  - [ ] HMAC_SHA384
  - [ ] HMAC_SHA512
- CIPHER:
  - [ ] RC4_128
  - [ ] 3DES_EDE_CBC
  - [ ] AES_128_CBC
  - [ ] AES_256_CBC
- CERT:
  - [ ] X.509v3 decoder
- SIGNATURES:
  - [ ] RSA_PKCS1 (v1.5)
  - [ ] DSA (DSS)
  - [ ] ECDSA
- HASH:
  - [ ] MD5
  - [ ] SHA1
  - [ ] SHA224
  - [ ] SHA256
  - [ ] SHA384
  - [ ] SHA512
- KEY EXCHANGE:
  - [ ] RSA_PSK
  - [ ] RSA
  - [ ] DH_RSA
  - [ ] DHE_RSA
  - [ ] DH_DSA (DSS)
  - [ ] DHE_DSA (DSS)
  - [ ] ECDH_RSA
  - [ ] ECDHE_RSA
  - [ ] ECDH_ECDSA
  - [ ] ECDHE_ECDSA

## TLS 1.3
REF: https://datatracker.ietf.org/doc/html/rfc8446

Similarly to version 1.2, there is a lot of code that needs to be written for the TLS 1.3 Client, but it is best to first fill in the basic building cryptographic building blocks:

- KEY EXCHANGE:
  - [ ] DHE (all finite fields?)
  - [ ] ECDHE_SECP256r1
  - [ ] ECDHE_x25519
  - [ ] PSK (+ (EC)DHE)
- SIGNATURE:
  - RSA PKCS1
    - [ ] RSA_PKCS1_SHA256
    - [ ] RSA_PKCS1_SHA384
    - [ ] RSA_PKCS1_SHA512
  - RSA PSS (RSAE OID + RSASSA-PSS OID)
    - [ ] RSA_PSS_SHA256
    - [ ] RSA_PSS_SHA384
    - [ ] RSA_PSS_SHA256
  - ECDSA
    - [ ] ECDSA_SECP256r1_SHA256
    - [ ] ECDSA_SECP384r1_SHA384
    - [ ] ECDSA_SECP521r1_SHA512
  - edDSA
    - [ ] EDDSA_X25519
    - [ ] EDDSA_X448
- GROUPS:
  - ECC
    - [ ] SECP256r1
    - [ ] SECP384r1
    - [ ] SECP521r1
    - [ ] X25519
    - [ ] X448
  - FiniteField
    - [ ] FFDHE_2048
    - [ ] FFDHE_3072
    - [ ] FFDHE_4096
    - [ ] FFDHE_6144
    - [ ] FFDHE_8192
- CERTIFICATE:
  - [ ] RawPublicKey Decoding
  - [ ] X509v3 Decoding
- CIPHERS:
  - [ ] AES128_GCM_SHA256
  - [ ] AES256_GCM_SHA384
  - [ ] AES128_CCM_SHA256
  - [ ] AES256_CCM8_SHA256
  - [ ] CHACHA20_POLY1305_SHA256
- KEY DERIVATION:
  - [ ] HKDF

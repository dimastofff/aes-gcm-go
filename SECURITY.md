# Security

## Reporting a vulnerability

Please avoid posting vulnerability details, exploit code, or affected secrets in
public issues or pull requests. If GitHub private vulnerability reporting is
enabled for this repository, use [Report a vulnerability](https://github.com/dimastofff/aes-gcm-go/security/advisories/new)
in the repository's Security tab.

If that private reporting option is unavailable, request a private contact method
from the maintainer without disclosing the vulnerability publicly. This repository
does not currently publish a separate security email address or response-time
commitment.

A private report should include the affected package and Go versions, platform,
reproduction steps, expected and observed behavior, and an explanation of the
impact. Use synthetic data and test keys rather than production secrets.

## Security support scope

The security-fix target is the latest released v1.x version (currently v1.1.0).
Users of earlier versions should upgrade; separate backports to older releases
are not part of this policy. This scope does not promise a response or release
schedule.

Go 1.13 is the source-compatibility baseline, not a recommendation to deploy that
runtime. Production applications should use the latest patch release of a Go
version covered by the [Go release support policy](https://go.dev/doc/devel/release#policy).
CI follows the current `stable` and `oldstable` releases and checks the legacy
compatibility baseline separately.

## Application responsibilities

The package uses the Go standard library's AES-256-GCM with a random 12-byte nonce,
a 16-byte authentication tag, and no additional authenticated data. Its wire
format is `nonce || ciphertext || tag`.

Keep keys secret and generate them from 32 cryptographically random bytes. The
base64 key input is an encoding of those bytes, not a password-based key derivation
scheme. Count encryptions across all uses of a key and rotate before exceeding
2^32 messages, as described by the [Go GCM nonce guidance](https://pkg.go.dev/crypto/cipher#example-NewGCM-Encrypt).
The package does not enforce this limit or manage keys and rotation.

Authentication of ciphertext alone does not prevent replay or establish freshness,
identity, or record ownership. The API cannot authenticate external metadata via
AAD. Any external key ID or other security-relevant metadata needs its own
trusted storage or authenticated protocol.

Whole messages and plaintext copies reside in memory. Applications must set their
own input-size limits and protect their process, memory, key storage, and
configuration. The package provides no secure-memory-erasure guarantee, and Go's
cryptographic implementation and hardware determine timing characteristics; see
the [standard library AES documentation](https://pkg.go.dev/crypto/aes).

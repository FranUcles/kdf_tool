# KDF Tool

**KDF Tool** is a Python library for deriving cryptographic keys using Argon2id and HKDF.

It provides a modular implementation that allows users to derive key material from passwords or other secrets, and subsequently generate multiple independent cryptographic keys using HKDF.

The library is designed to provide a clear and reusable key derivation workflow, with input validation, immutable result objects, and an explicit derivation context.

---

## Table of contents

- [Features](#features)
- [Cryptographic foundations](#cryptographic-foundations)
  - [Argon2id](#argon2id)
  - [HKDF](#hkdf)
  - [Combined derivation workflow](#combined-derivation-workflow)
- [Installation](#installation)
- [Project structure](#project-structure)
- [Usage](#usage)
  - [Argon2id derivation](#argon2id-derivation)
  - [HKDF derivation](#hkdf-derivation)
  - [Combined derivation](#combined-derivation)
  - [Deriving multiple keys](#deriving-multiple-keys)
  - [Using the derivation context](#using-the-derivation-context)
- [Supported hash algorithms](#supported-hash-algorithms)
- [Validation and exceptions](#validation-and-exceptions)
- [Security considerations](#security-considerations)
- [Development](#development)
- [Testing](#testing)
- [License](#license)

---

## Features

- **Argon2id key derivation:** derive cryptographic key material from passwords or other secrets.
- **Configurable Argon2id parameters:** control memory cost, time cost, parallelism, and output length.
- **Automatic salt generation:** generate a random salt for each Argon2id derivation.
- **HKDF implementation:** perform key derivation using the Extract and Expand stages defined in RFC 5869.
- **Multiple hash algorithms:** support SHA-256, SHA-384, and SHA-512.
- **Combined derivation workflow:** execute Argon2id and HKDF Extract once, then derive multiple independent keys.
- **Explicit derivation requests:** specify a name, output length, and context information for every derived key.
- **Immutable result objects:** protect returned derivation results against accidental modification.
- **Derivation context management:** keep intermediate key material private and provide an explicit lifecycle through `close()` and context managers.
- **Input validation:** validate argument types, lengths, supported algorithms, and derivation constraints.

---

## Cryptographic foundations

KDF Tool combines two cryptographic constructions with different purposes.

### Argon2id

Argon2id is a password-based key derivation function specified in RFC 9106.

It is designed to make password guessing more expensive by requiring significant computational and memory resources.

Argon2id is particularly useful when the input material is a human-generated password or another secret with relatively low entropy.

The derivation can be represented as:

```text
Password / Secret
        |
        v
     Argon2id
        |
        v
   Derived Key
```

Argon2id uses the following configurable parameters:

| Parameter | Description |
|---|---|
| `time_cost` | Number of iterations |
| `memory_cost` | Memory usage in KiB |
| `parallelism` | Number of parallel lanes |
| `hash_len` | Length of the resulting key in bytes |
| `salt` | Random salt generated for each derivation |

The salt is generated internally using Python's `secrets` module.

The resulting object contains the derived key, salt, algorithm identifier, version, and parameters.

### HKDF

HKDF (HMAC-based Extract-and-Expand Key Derivation Function) is specified in RFC 5869.

It derives one or more cryptographically independent keys from existing input key material.

HKDF consists of two stages:

**1. Extract**

Extract converts the input key material into a pseudorandom key (PRK):

```text
PRK = HMAC(salt, IKM)
```

**2. Expand**

Expand generates output key material (OKM) using the PRK and optional context information:

```text
T(0) = empty

T(1) = HMAC(PRK, T(0) || info || 0x01)
T(2) = HMAC(PRK, T(1) || info || 0x02)
...
```

The resulting blocks are concatenated and truncated to the requested output length.

The `info` parameter provides context separation. It allows different keys to be derived for different cryptographic purposes.

For example:

- Encryption keys.
- Authentication keys.
- Signing-related key material, where the target scheme permits derived key material.
- Keys for different files or application components.

The maximum output length is limited to:

```text
L <= 255 * HashLen
```

where `HashLen` is the output length of the selected hash algorithm.

When no salt is provided, HKDF uses a zero-filled salt of the hash output length, as specified in RFC 5869.

### Combined derivation workflow

KDF Tool provides a higher-level workflow combining Argon2id and HKDF.

The process is:

```text
                  Password / Secret
                         |
                         v
                      Argon2id
                         |
                         v
                    Derived Key
                         |
                         v
                    HKDF Extract
                         |
                         v
                         PRK
                         |
             +-----------+-----------+
             |           |           |
             v           v           v
          Expand      Expand      Expand
             |           |           |
             v           v           v
          Key A       Key B       Key C
```

The important design decision is that Argon2id and HKDF Extract are executed only once per derivation context.

Every subsequent key request uses HKDF Expand with the same PRK.

This avoids repeating the expensive Argon2id computation when multiple keys are needed.

---

## Installation

KDF Tool requires Python and the `argon2-cffi` dependency.

Install the project in editable mode:

```bash
python -m pip install -e .
```

---

## Project structure

The library uses a `src` layout:

```text
mi_kdf/
│
├── src/
│   └── kdf_tool/
│       ├── __init__.py
│       ├── exceptions.py
│       │
│       ├── argon2/
│       │   ├── __init__.py
│       │   ├── config.py
│       │   └── derivation.py
│       │
│       ├── hkdf/
│       │   ├── __init__.py
│       │   ├── algorithms.py
│       │   ├── extract.py
│       │   ├── expand.py
│       │   └── derivation.py
│       │
│       └── context/
│           ├── __init__.py
│           ├── requests.py
│           ├── results.py
│           ├── derivation_context.py
│           └── factory.py
│
├── tests/
│   ├── argon2/
│   ├── hkdf/
│   ├── context/
│   └── integration/
│
├── pyproject.toml
└── README.md
```

Each package has a specific responsibility:

- `argon2`: Argon2id configuration and derivation.
- `hkdf`: hash algorithm metadata, Extract, Expand, and standalone HKDF derivation.
- `context`: derivation requests, result objects, context lifecycle, and the factory.
- `exceptions.py`: library-specific exceptions.

---

## Usage

### Argon2id derivation

Argon2id can be used independently when deriving key material from a password or secret.

```python
from kdf_tool import Argon2Config, derive_argon2id

config = Argon2Config(
    time_cost=3,
    memory_cost=262144,
    parallelism=4,
    hash_len=32
)

secret = b"my password"

result = derive_argon2id(
    secret=secret,
    config=config
)

derived_key = result.key
salt = result.salt

print(derived_key.hex())
print(salt.hex())
```

The result contains the derived key and the information required to identify the derivation parameters.

**Important:** the salt and configuration parameters must be retained if the same key needs to be reproduced later.

### HKDF derivation

HKDF can also be used independently when the input key material already has sufficient entropy.

```python
from kdf_tool import derive_hkdf

ikm = b"some sufficiently random input key material"

result = derive_hkdf(
    ikm=ikm,
    length=32,
    salt=None,
    info=b"encryption-key",
    hash_algorithm="sha256"
)

derived_key = result.key

print(derived_key.hex())
```

The `info` parameter should identify the intended purpose of the derived key.

Different context information produces different derived keys.

### Combined derivation

For workflows requiring multiple keys, the recommended approach is to use `DerivationFactory`.

The factory performs:

1. Argon2id derivation.
2. HKDF Extract.
3. Creation of a `DerivationContext`.

```python
from kdf_tool import (
    Argon2Config,
    DerivationFactory
)

config = Argon2Config(
    time_cost=3,
    memory_cost=262144,
    parallelism=4,
    hash_len=32
)

context = DerivationFactory.create(
    secret=b"my password",
    argon2_config=config,
    hkdf_salt=None,
    hash_algorithm="sha256"
)
```

The returned context can then be used to derive multiple keys.

### Deriving multiple keys

Each key is represented by an `HKDFDerivationRequest`.

A request explicitly defines:

- `name`: unique identifier for the key.
- `length`: requested key length in bytes.
- `info`: context information used by HKDF Expand.

Example:

```python
from kdf_tool import HKDFDerivationRequest

encryption_request = HKDFDerivationRequest(
    name="encryption",
    length=32,
    info=b"application/encryption"
)

authentication_request = HKDFDerivationRequest(
    name="authentication",
    length=32,
    info=b"application/authentication"
)
```

Derive the requested keys:

```python
encryption_result = context.derive_key(encryption_request)

authentication_result = context.derive_key(
    authentication_request
)

encryption_key = encryption_result.key
authentication_key = authentication_result.key
```

Each request is registered in the context, and names must be unique within that context.

### Using the derivation context

The derivation context supports retrieving previously derived keys and obtaining a combined result.

```python
encryption_result = context.get_key("encryption")

combined_result = context.get_result()
```

The combined result contains:

- The original Argon2id derivation result.
- The HKDF salt.
- The selected hash algorithm.
- The derivation requests.
- The derived keys.

The internal PRK is not exposed through the result object.

The context also supports explicit closure:

```python
context.close()
```

Once closed, the context cannot be used for further derivations or retrieval operations.

Calling `close()` multiple times is safe.

Alternatively, use a context manager:

```python
with DerivationFactory.create(
    secret=b"my password",
    argon2_config=config
) as context:

    encryption_result = context.derive_key(
        encryption_request
    )

    authentication_result = context.derive_key(
        authentication_request
    )

    combined_result = context.get_result()
```

The context is automatically closed when execution leaves the `with` block.

---

## Supported hash algorithms

KDF Tool currently supports the following hash algorithms for HKDF:

| Algorithm | Hash length |
|---|---:|
| SHA-256 | 32 bytes |
| SHA-384 | 48 bytes |
| SHA-512 | 64 bytes |

The supported identifiers are:

```python
from kdf_tool import AVAILABLE_HASH_ALGORITHMS

print(AVAILABLE_HASH_ALGORITHMS)
```

---

## Validation and exceptions

The library validates its public inputs and result objects.

Validation includes:

- Correct input types.
- Non-empty secrets and key material where required.
- Valid Argon2id configuration parameters.
- Supported hash algorithms.
- Valid HKDF output lengths.
- Correct PRK length for the selected hash algorithm.
- Unique derivation request names.
- Consistent result metadata.

The library defines `Argon2DerivationException` for failures in the Argon2id derivation process.

Invalid arguments generally raise Python's standard `TypeError` or `ValueError`, while missing keys raise `KeyError`.

---

## Security considerations

KDF Tool provides key derivation primitives. It does not implement encryption, digital signatures, key storage, or secure file handling.

Users are responsible for integrating the resulting keys into appropriate cryptographic protocols.

### Entropy

Neither Argon2id nor HKDF creates entropy.

Argon2id increases the computational cost of guessing low-entropy secrets.

HKDF derives pseudorandom key material from existing input key material.

If the input is already sufficiently random, HKDF can be used directly without Argon2id.

### Salt management

The Argon2id salt is generated randomly for each derivation.

It is not secret, but it must be retained alongside the relevant parameters if the derived key needs to be reproduced.

The HKDF salt is a separate value with a different purpose. It is provided by the caller and may be omitted according to RFC 5869.

### Context separation

Use distinct `info` values for different cryptographic purposes.

For example:

```python
b"application/encryption"
b"application/authentication"
b"application/file-metadata"
```

This prevents different uses of the same PRK from accidentally producing the same derived key.

### Key lifecycle

The derivation context keeps the PRK private and removes its internal reference when closed.

However, Python does not guarantee secure memory erasure. Immutable `bytes` objects and copies may remain in memory until reclaimed.

Closing a context should therefore not be interpreted as guaranteed physical erasure of all sensitive material.

### Cryptographic operations

Derived keys must be used with cryptographic algorithms and protocols that accept the corresponding key lengths and formats.

For example, AES-GCM is an authenticated encryption mode and normally does not require an additional HMAC for message authentication.

Digital signature schemes have their own key generation and encoding requirements. Arbitrary HKDF output must not be assumed to be a valid private key without following the relevant scheme's specification.

---

## Development

Clone the repository and install the package in editable mode:

```bash
python -m pip install -e .
```

For development, install the test dependencies:

```bash
python -m pip install pytest
```

Run the test suite:

```bash
python -m pytest -v
```

The tests are organized by package and functionality:

- Argon2id configuration and derivation.
- HKDF Extract and Expand.
- Standalone HKDF derivation.
- Derivation requests and results.
- Derivation context lifecycle.
- Factory behavior.
- Integration workflows.

---

## Testing

The project includes unit tests and integration tests.

The test suite covers:

- Valid and invalid inputs.
- Argon2id parameter validation.
- Salt generation.
- HKDF behavior for supported hash algorithms.
- HKDF output length restrictions.
- RFC 5869 test vectors.
- Multiple independent key derivations.
- Duplicate request names.
- Context closure and lifecycle.
- Factory orchestration.
- Result consistency and immutability.

Run all tests with:

```bash
python -m pytest -v
```

---

## Standards and references

The implementation is based on the following standards:

- **RFC 9106:** Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications.
  https://www.rfc-editor.org/rfc/rfc9106

- **RFC 5869:** HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
  https://www.rfc-editor.org/rfc/rfc5869

---

## License

License information will be added when the project's licensing terms are finalized.
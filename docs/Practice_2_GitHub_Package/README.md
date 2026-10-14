# Practice 2: Symmetric Cryptography

**Course:** Theory of Codes and Cryptography  
**Implementation language:** Python 3  
**Authors:** Daniel Nazaruk, Adam Gryniewski, Lucjan Jacek Pucelak, Anas Rakssa Zargaoui

## 1. Libraries used

| Library / module | Main characteristics | Role in the application |
|---|---|---|
| `cryptography` | Provides AES, CBC, PKCS#7 padding, PBKDF2-HMAC, HKDF, HMAC, and AES key wrapping. | Encrypts/decrypts bytes, derives key-encryption material, wraps the random data key, and authenticates the encrypted container. |
| `secrets` (Python standard library; reused from Practice 1) | Uses the operating system's cryptographic randomness source. | Generates a fresh 32-byte AES key, a 16-byte IV, and a unique 16-byte salt for each encryption operation. |
| `Flask` (reused from Practice 1) | Lightweight web framework for HTTP routes and request handling. | Provides the existing API interface for submitting text/files and returning results. It does not perform cryptographic operations itself. |
| `pathlib` (Python standard library) | Cross-platform file path handling. | Manages input, temporary, encrypted, and restored-file paths. |

**Scope note:** `liboqs-python` was included in Practice 1 for ML-KEM key establishment and ML-DSA signatures. It is not needed for the standalone AES-CBC path in this assignment, but may be integrated into the wider hybrid design separately.

## 2. Process flow

![Encryption and decryption workflows](practice2_workflow.png)

### Encryption

1. Accept plaintext or read the selected file in binary mode.
2. Generate a fresh 256-bit data-encryption key (DEK), a fresh 128-bit IV, and a unique salt using `secrets.token_bytes()`.
3. Apply PKCS#7 padding and encrypt the padded bytes using AES-256-CBC.
4. Derive a key-encryption key (KEK) from the user's password, wrap the DEK, and calculate an HMAC-SHA-256 authentication tag over the canonical container fields.
5. Write the encrypted container to a new file and verify the write. Only then replace or remove the source according to the application's policy.

### Decryption

1. Read the metadata, salt, wrapped DEK, IV, ciphertext, and authentication tag.
2. Ask for the password, derive the KEK again, and unwrap the DEK.
3. Verify the HMAC tag before decryption. Reject modified data or an incorrect password.
4. Decrypt with AES-CBC, remove PKCS#7 padding, and write the recovered data to a new file.
5. Verify the restored output before removing the encrypted copy.

## 3. Supported file types and encrypted output

Files are processed as bytes, so the application does not need to interpret their format. Supported examples include text/data files (`.txt`, `.csv`, `.json`), images (`.jpg`, `.png`, `.gif`), documents (`.pdf`, `.docx`, `.xlsx`), audio/video (`.mp3`, `.mp4`, `.wav`), archives (`.zip`, `.7z`), and executable or other binary files.

The output is a binary `.enc` container containing a version/algorithm identifier, KDF information and parameters, salt, wrapped DEK, 16-byte IV, ciphertext, and 32-byte HMAC-SHA-256 tag. PKCS#7 padding makes the ciphertext length a multiple of 16 bytes. The IV, salt, and KDF parameters are not secret, but must be stored correctly. The `.enc` extension is only a naming convention.

The output must be written and checked before the original file is removed. Ordinary deletion does not guarantee secure erasure on SSDs, journaling file systems, snapshots, backups, or cloud-synced folders.

## 4. Cryptosystem description and justification

| Parameter | Choice | Justification |
|---|---|---|
| Algorithm | AES | Widely deployed symmetric block cipher with standardized implementations. |
| Key length | 256 bits (32 bytes) | Strong symmetric key length; the key must be securely generated and protected. |
| Block length | 128 bits (16 bytes) | AES has a fixed 128-bit block size. |
| Mode | CBC | Required by the assignment; each plaintext block is combined with the preceding ciphertext block, while the first uses the IV. |
| IV | Fresh, unpredictable 128-bit value per encryption | Matches the AES block size. It is not secret but must be stored with ciphertext and not reused with the same key. |
| Padding | PKCS#7 | Extends data to a multiple of 16 bytes and allows removal after decryption. |
| Integrity | HMAC-SHA-256, checked before decryption | CBC alone does not detect tampering. The tag authenticates the container fields and ciphertext. |
| Input/output | Bytes; text encoded as UTF-8 | Supports both text input and arbitrary files. |

CBC is retained to satisfy the exercise. For a new production design, authenticated encryption such as AES-GCM is generally preferable because it provides confidentiality and integrity together. Mini-AES is only an educational toy cipher and must not be used to protect real data.

## 5. Key selection, storage, and security

A fresh DEK is generated for each encryption with `secrets.token_bytes(32)`. The application also generates a new 16-byte IV and a unique 16-byte salt. The application cannot discard the key unless it preserves a protected way to recover it.

The proposed envelope-encryption process is:

1. Encrypt the padded input with the fresh DEK and AES-256-CBC.
2. Derive a 256-bit key-encryption key (KEK) from the user's master password using PBKDF2-HMAC-SHA-256, the stored salt, and a suitably high documented iteration count.
3. Wrap the DEK with the KEK using AES key wrap. Store the wrapped DEK, salt, and KDF parameters, but never store the raw DEK or password.
4. Derive a separate MAC key from the DEK using HKDF-SHA-256 and an application-specific context label. Use HMAC-SHA-256 to authenticate the version, KDF metadata, wrapped key, IV, and ciphertext.
5. On decryption, derive the KEK, unwrap the DEK, derive the MAC key, and verify the HMAC before decrypting. Stop if any check fails.

The password must not be stored or logged. The salt and KDF parameters are public but necessary for key recovery. Losing the password may make the encrypted data unrecoverable. A broader integration with the Practice 1 hybrid design could replace password-based key wrapping with an ML-KEM-based key-establishment step; that is separate from the symmetric demonstration.

## 6. Mini-AES encryption and decryption in CBC mode

This example uses Phan's Mini-AES variant as documented by SageMath. It is a 16-bit educational cipher with a 16-bit key, not standard AES. The 32-bit plaintext is split into two 16-bit blocks. This variant is explicitly identified because the assignment does not specify a Mini-AES S-box or key schedule.

### 6.1 Given data

```text
P  = 10101000001010111011111010010011
P1 = 1010100000101011 (A82B)
P2 = 1011111010010011 (BE93)
K  = 1100110011000111 (CCC7)
IV = 0000001100111101 (033D)
```

CBC rules:

```text
C1 = E_K(P1 XOR IV)
C2 = E_K(P2 XOR C1)
P1 = D_K(C1) XOR IV
P2 = D_K(C2) XOR C1
```

### 6.2 Round keys

```text
K0 = 1100110011000111 (CCC7)
K1 = 0101010110010010 (5592)
K2 = 1010011000110100 (A634)
```

The encryption steps are AddRoundKey K0, SubNibble, ShiftRow, MixColumn, AddRoundKey K1, SubNibble, ShiftRow, and the final AddRoundKey K2.

### 6.3 Encrypt the first block

1. `P1 XOR IV = 1010100000101011 XOR 0000001100111101 = 1010101100010110 (AB16)`
2. Add K0: `AB16 XOR CCC7 = 67D1 = 0110011111010001`
3. SubNibble: `B894 = 1011100010010100`
4. ShiftRow: `B849 = 1011100001001001`
5. MixColumn: `6A9B = 0110101010011011`
6. Add K1: `6A9B XOR 5592 = 3F09 = 0011111100001001`
7. SubNibble: `17EA = 0001011111101010`
8. ShiftRow: `17AE = 0001011110101110`
9. Final Add K2: `17AE XOR A634 = B19A = 1011000110011010`

Therefore, `C1 = 1011000110011010`.

### 6.4 Encrypt the second block

1. `P2 XOR C1 = 1011111010010011 XOR 1011000110011010 = 0000111100001001 (0F09)`
2. Add K0: `0F09 XOR CCC7 = C3CE = 1100001111001110`
3. SubNibble: `5150 = 0101000101010000`
4. ShiftRow: `5105 = 0101000100000101`
5. MixColumn: `F9AD = 1111100110101101`
6. Add K1: `F9AD XOR 5592 = AC3F = 1010110000111111`
7. SubNibble: `6517 = 0110010100010111`
8. ShiftRow: `6571 = 0110010101110001`
9. Final Add K2: `6571 XOR A634 = C345 = 1100001101000101`

Therefore, `C2 = 1100001101000101`.

**Final ciphertext:** `1011000110011010 1100001101000101`

### 6.5 Decrypt and recover the original plaintext

Decryption reverses the encryption rounds. First undo K2, then apply inverse ShiftRow and inverse SubNibble, undo K1, apply MixColumn and ShiftRow, apply inverse SubNibble, and undo K0.

**First block:**

1. `C1 XOR K2 = B19A XOR A634 = 17AE`
2. Inverse ShiftRow: `17EA`
3. Inverse SubNibble: `3F09`
4. XOR K1: `3F09 XOR 5592 = 6A9B`
5. MixColumn: `B849`
6. Inverse ShiftRow: `B894`
7. Inverse SubNibble: `67D1`
8. XOR K0: `67D1 XOR CCC7 = AB16`
9. CBC XOR with IV: `AB16 XOR 033D = 1010100000101011 = P1`

**Second block:**

1. `C2 XOR K2 = C345 XOR A634 = 6571`
2. Inverse ShiftRow: `6517`
3. Inverse SubNibble: `AC3F`
4. XOR K1: `AC3F XOR 5592 = F9AD`
5. MixColumn: `5105`
6. Inverse ShiftRow: `5150`
7. Inverse SubNibble: `C3CE`
8. XOR K0: `C3CE XOR CCC7 = 0F09`
9. CBC XOR with C1: `0F09 XOR B19A = 1011111010010011 = P2`

**Recovered plaintext:** `10101000001010111011111010010011`

The recovered 32-bit plaintext matches the original input exactly.

## References

1. SageMath Development Team. [Mini-AES, SageMath Reference Manual](https://doc.sagemath.org/html/en/reference/cryptography/sage/crypto/block_cipher/miniaes.html).
2. The Python Cryptographic Authority. [Symmetric encryption documentation](https://cryptography.io/en/stable/hazmat/primitives/symmetric-encryption/).
3. National Institute of Standards and Technology. [Advanced Encryption Standard (AES), FIPS 197](https://csrc.nist.gov/pubs/fips/197/final).
4. Python Software Foundation. [secrets module documentation](https://docs.python.org/3/library/secrets.html).
5. Pallets Projects. [Flask documentation](https://flask.palletsprojects.com/).

*Variant note: the numerical example adopts Phan's Mini-AES as documented by SageMath. Results may differ if the instructor uses another classroom variant.*

# novice-webcrypto

> Simplify browser cryptography with safe, easy-to-use TypeScript classes.  
> Built for developers who dislike the verbose native Web Crypto API.  
> Every key is a **Base64-safe string** — easy to store, transfer, and reuse.

---

## Features

- AES-GCM symmetric encryption/decryption
- RSA-OAEP encryption / RSASSA-PKCS1-v1_5 signature
- ECDSA (P-256) signature and verification
- Key generation and import/export as **Base64 strings**
- Zero crypto dependencies — uses native Web Crypto API

---

## Installation

`npm install novice-webcrypto`

or

`pnpm add novice-webcrypto`

---

## Example Usage

### AES-GCM Encryption & Decryption

```ts
import { AES } from "novice-webcrypto";

// Generate a new AES key
const key = await AES.generateKey();

// Encrypt
const { iv, ciphertext } = await AES.encrypt(key, "Hello World");

// Decrypt
const plaintext = await AES.decrypt(key, iv, ciphertext);
console.log(plaintext); // Hello World\
```

---

### ECDSA Sign & Verify

```ts
import { ECDSA } from "novice-webcrypto";

const { publicKey, privateKey } = await ECDSA.generateKeyPair();

const message = "Important message";
const signature = await ECDSA.sign(privateKey, message);

const valid = await ECDSA.verify(publicKey, message, signature);
console.log(valid); // true
```

---

### RSA Encryption Example

```ts
import { RSA } from "novice-webcrypto";

const { publicKey, privateKey } = await RSA.generateKeyPair();

const plaintext = "Secret message";
const ciphertext = await RSA.encrypt(publicKey, plaintext);

const decrypted = await RSA.decrypt(privateKey, ciphertext);
console.log(decrypted); // Secret message
```

---

## API Summary

- `AES.generateKey()` → base64 key
- `AES.encrypt(base64Key, plaintext)` → { iv, ciphertext }
- `AES.decrypt(base64Key, iv, ciphertext)` → plaintext

- `ECDSA.generateKeyPair()` → { publicKey, privateKey } (base64 JWK)
- `ECDSA.sign(privateKey, message)` → signature (base64)
- `ECDSA.verify(publicKey, message, signature)` → boolean

- `RSA.generateKeyPair()` → { publicKey, privateKey } (base64 PEM or JWK)
- `RSA.encrypt(publicKey, plaintext)` → ciphertext (base64)
- `RSA.decrypt(privateKey, ciphertext)` → plaintext

---

## License

MIT License © 2025 Lê Minh Quân

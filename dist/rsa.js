import { arrayBufferToBase64, base64ToArrayBuffer } from "./helper";
// rsa.ts
export class RSA {
    /**
     * Generate a new RSA-OAEP key pair (2048-bit, SHA-256).
    *  @returns [public key, private key]
     */
    static async generateKeyPair() {
        const keypair = await crypto.subtle.generateKey({
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        }, true, ["encrypt", "decrypt"]);
        const spki_pub = await crypto.subtle.exportKey("spki", keypair.publicKey);
        const pkcs8_priv = await crypto.subtle.exportKey("pkcs8", keypair.privateKey);
        const pub_base64 = arrayBufferToBase64(spki_pub);
        const priv_base64 = arrayBufferToBase64(pkcs8_priv);
        return [pub_base64, priv_base64];
    }
    /**
     * Import a public key from a base64 SPKI string.
     */
    static async importPublicKey(base64) {
        const spki = base64ToArrayBuffer(base64);
        return crypto.subtle.importKey("spki", spki, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
    }
    /**
     * Import a private key from a base64 PKCS#8 string.
     */
    static async importPrivateKey(base64) {
        const pkcs8 = base64ToArrayBuffer(base64);
        return crypto.subtle.importKey("pkcs8", pkcs8, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
    }
    /**
     * Encrypt a plaintext string using a public key.
     */
    static async encrypt(publicKey, plaintext) {
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);
        const importedKey = await RSA.importPublicKey(publicKey);
        const ciphertext = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, importedKey, data);
        return arrayBufferToBase64(ciphertext);
    }
    /**
     * Decrypt a base64 ciphertext string using a private key.
     */
    static async decrypt(privateKey, ciphertextBase64) {
        const ciphertext = base64ToArrayBuffer(ciphertextBase64);
        const importedKey = await RSA.importPrivateKey(privateKey);
        const decrypted = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, importedKey, ciphertext);
        return new TextDecoder().decode(decrypted);
    }
    /**
     * Sign a plaintext string using a private key.
     */
    static async sign(privateKey, plaintext) {
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);
        const importedKey = await RSA.importPrivateKey(privateKey);
        const signature = await crypto.subtle.sign({ name: "RSA-PSS" }, importedKey, data);
        return arrayBufferToBase64(signature);
    }
    /**
     * Verify a signature using a public key.
     */
    static async verify(publicKey, plaintext, signatureBase64) {
        const signature = base64ToArrayBuffer(signatureBase64);
        const importedKey = await RSA.importPublicKey(publicKey);
        return crypto.subtle.verify({ name: "RSA-PSS" }, importedKey, signature, new TextEncoder().encode(plaintext));
    }
}

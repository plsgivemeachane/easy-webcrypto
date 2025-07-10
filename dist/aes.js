import { arrayBufferToBase64, base64ToArrayBuffer } from "./helper";
export class AES {
    /**
     * Generate a new AES-GCM key (256-bit).
     */
    static async generateKey() {
        const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
            "encrypt",
            "decrypt",
        ]);
        const raw = await crypto.subtle.exportKey("raw", key);
        return arrayBufferToBase64(raw);
    }
    /**
     * Import a base64 key string to CryptoKey.
     */
    static async importKey(base64) {
        const raw = base64ToArrayBuffer(base64);
        return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, true, [
            "encrypt",
            "decrypt",
        ]);
    }
    /**
     * Encrypt a plaintext string, return iv and ciphertext as base64.
     */
    static async encrypt(key, plaintext) {
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);
        const iv = crypto.getRandomValues(new Uint8Array(12)); // AES-GCM recommends 12-byte IV
        const importedKey = await AES.importKey(key);
        const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, importedKey, data);
        return {
            iv: arrayBufferToBase64(iv),
            ciphertext: arrayBufferToBase64(ciphertext),
        };
    }
    /**
     * Decrypt a base64 ciphertext string using the key and iv.
     */
    static async decrypt(key, ivBase64, ciphertextBase64) {
        const iv = base64ToArrayBuffer(ivBase64);
        const ciphertext = base64ToArrayBuffer(ciphertextBase64);
        const importedKey = await AES.importKey(key);
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(iv) }, importedKey, ciphertext);
        return new TextDecoder().decode(decrypted);
    }
}

export declare class AES {
    /**
     * Generate a new AES-GCM key (256-bit).
     */
    static generateKey(): Promise<string>;
    /**
     * Import a base64 key string to CryptoKey.
     */
    static importKey(base64: string): Promise<CryptoKey>;
    /**
     * Encrypt a plaintext string, return iv and ciphertext as base64.
     */
    static encrypt(key: string, plaintext: string): Promise<{
        iv: string;
        ciphertext: string;
    }>;
    /**
     * Decrypt a base64 ciphertext string using the key and iv.
     */
    static decrypt(key: string, ivBase64: string, ciphertextBase64: string): Promise<string>;
}

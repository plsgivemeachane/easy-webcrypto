export declare class RSA {
    /**
     * Generate a new RSA-OAEP key pair (2048-bit, SHA-256).
    *  @returns [public key, private key]
     */
    static generateKeyPair(): Promise<[string, string]>;
    /**
     * Import a public key from a base64 SPKI string.
     */
    static importPublicKey(base64: string): Promise<CryptoKey>;
    /**
     * Import a private key from a base64 PKCS#8 string.
     */
    static importPrivateKey(base64: string): Promise<CryptoKey>;
    /**
     * Encrypt a plaintext string using a public key.
     */
    static encrypt(publicKey: string, plaintext: string): Promise<string>;
    /**
     * Decrypt a base64 ciphertext string using a private key.
     */
    static decrypt(privateKey: string, ciphertextBase64: string): Promise<string>;
    /**
     * Sign a plaintext string using a private key.
     */
    static sign(privateKey: string, plaintext: string): Promise<string>;
    /**
     * Verify a signature using a public key.
     */
    static verify(publicKey: string, plaintext: string, signatureBase64: string): Promise<boolean>;
}

export declare class ECDSA {
    /**
     * Generate a new ECDSA key pair (P-256 curve, SHA-256 hash).
     * Returns base64-encoded public and private keys in JWK format.
     */
    static generateKeyPair(): Promise<{
        publicKey: string;
        privateKey: string;
    }>;
    /**
     * Import a base64-encoded JWK public key.
     */
    static importPublicKey(base64: string): Promise<CryptoKey>;
    /**
     * Import a base64-encoded JWK private key.
     */
    static importPrivateKey(base64: string): Promise<CryptoKey>;
    /**
     * Sign a plaintext message, returning the signature as base64.
     */
    static sign(privateKey: string, message: string): Promise<string>;
    /**
     * Verify a signature with the public key and original message.
     */
    static verify(publicKey: string, message: string, signatureBase64: string): Promise<boolean>;
}

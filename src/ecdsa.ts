import { arrayBufferToBase64, base64SafeToString, base64ToArrayBuffer, stringToBase64Safe } from './helper';

export class ECDSA {
    /**
     * Generate a new ECDSA key pair (P-256 curve, SHA-256 hash).
     * Returns base64-encoded public and private keys in JWK format.
     */
    static async generateKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
        const keyPair = await crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: 'P-256',
            },
            true,
            ['sign', 'verify']
        );

        const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
        const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

        return {
            publicKey: stringToBase64Safe(JSON.stringify(publicKeyJwk)),
            privateKey: stringToBase64Safe(JSON.stringify(privateKeyJwk)),
        };
    }

    /**
     * Import a base64-encoded JWK public key.
     */
    static async importPublicKey(base64: string): Promise<CryptoKey> {
        const jwk = JSON.parse(base64SafeToString(base64));
        return crypto.subtle.importKey(
            'jwk',
            jwk,
            {
                name: 'ECDSA',
                namedCurve: 'P-256',
            },
            true,
            ['verify']
        );
    }

    /**
     * Import a base64-encoded JWK private key.
     */
    static async importPrivateKey(base64: string): Promise<CryptoKey> {
        const jwk = JSON.parse(base64SafeToString(base64));
        return crypto.subtle.importKey(
            'jwk',
            jwk,
            {
                name: 'ECDSA',
                namedCurve: 'P-256',
            },
            true,
            ['sign']
        );
    }

    /**
     * Sign a plaintext message, returning the signature as base64.
     */
    static async sign(privateKey: string, message: string): Promise<string> {
        const importedPrivateKey = await ECDSA.importPrivateKey(privateKey);
        const data = new TextEncoder().encode(message);
        const signature = await crypto.subtle.sign(
            {
                name: 'ECDSA',
                hash: { name: 'SHA-256' },
            },
            importedPrivateKey,
            data
        );
        return arrayBufferToBase64(signature);
    }

    /**
     * Verify a signature with the public key and original message.
     */
    static async verify(publicKey: string, message: string, signatureBase64: string): Promise<boolean> {
        const importedPublicKey = await ECDSA.importPublicKey(publicKey);
        const data = new TextEncoder().encode(message);
        const signature = base64ToArrayBuffer(signatureBase64);
        return crypto.subtle.verify(
            {
                name: 'ECDSA',
                hash: { name: 'SHA-256' },
            },
            importedPublicKey,
            signature,
            data
        );
    }
}

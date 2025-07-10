"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ECDSA = void 0;
const helper_1 = require("./helper");
class ECDSA {
    /**
     * Generate a new ECDSA key pair (P-256 curve, SHA-256 hash).
     * Returns base64-encoded public and private keys in JWK format.
     */
    static async generateKeyPair() {
        const keyPair = await crypto.subtle.generateKey({
            name: 'ECDSA',
            namedCurve: 'P-256',
        }, true, ['sign', 'verify']);
        const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
        const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
        return {
            publicKey: (0, helper_1.stringToBase64Safe)(JSON.stringify(publicKeyJwk)),
            privateKey: (0, helper_1.stringToBase64Safe)(JSON.stringify(privateKeyJwk)),
        };
    }
    /**
     * Import a base64-encoded JWK public key.
     */
    static async importPublicKey(base64) {
        const jwk = JSON.parse((0, helper_1.base64SafeToString)(base64));
        return crypto.subtle.importKey('jwk', jwk, {
            name: 'ECDSA',
            namedCurve: 'P-256',
        }, true, ['verify']);
    }
    /**
     * Import a base64-encoded JWK private key.
     */
    static async importPrivateKey(base64) {
        const jwk = JSON.parse((0, helper_1.base64SafeToString)(base64));
        return crypto.subtle.importKey('jwk', jwk, {
            name: 'ECDSA',
            namedCurve: 'P-256',
        }, true, ['sign']);
    }
    /**
     * Sign a plaintext message, returning the signature as base64.
     */
    static async sign(privateKey, message) {
        const importedPrivateKey = await ECDSA.importPrivateKey(privateKey);
        const data = new TextEncoder().encode(message);
        const signature = await crypto.subtle.sign({
            name: 'ECDSA',
            hash: { name: 'SHA-256' },
        }, importedPrivateKey, data);
        return (0, helper_1.arrayBufferToBase64)(signature);
    }
    /**
     * Verify a signature with the public key and original message.
     */
    static async verify(publicKey, message, signatureBase64) {
        const importedPublicKey = await ECDSA.importPublicKey(publicKey);
        const data = new TextEncoder().encode(message);
        const signature = (0, helper_1.base64ToArrayBuffer)(signatureBase64);
        return crypto.subtle.verify({
            name: 'ECDSA',
            hash: { name: 'SHA-256' },
        }, importedPublicKey, signature, data);
    }
}
exports.ECDSA = ECDSA;

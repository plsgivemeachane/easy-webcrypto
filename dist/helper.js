/** Helper: ArrayBuffer → Base64 */
export function arrayBufferToBase64(buffer) {
    const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    // Convert to URL-safe base64
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function urlSafeBase64ToBase64(urlSafe) {
    let base64 = urlSafe.replace(/-/g, '+').replace(/_/g, '/');
    // Add padding if needed
    const padLength = (4 - (base64.length % 4)) % 4;
    base64 += '='.repeat(padLength);
    return base64;
}
export function base64ToArrayBuffer(base64) {
    const binary = atob(urlSafeBase64ToBase64(base64));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}
export function stringToBase64Safe(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const base64 = btoa(String.fromCharCode(...new Uint8Array(data)));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function base64SafeToString(base64) {
    const decoder = new TextDecoder();
    const data = base64ToArrayBuffer(urlSafeBase64ToBase64(base64));
    return decoder.decode(data);
}

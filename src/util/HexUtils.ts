export function bytesToHexString(bytes) {
    return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, "0"), "");
}


export function bytesFromHexString(hexString) {
    const match = hexString.match(/.{1,2}/g);
    if (!match) {
        throw new Error("String does not seem to be in HEX");
    }
    return new Uint8Array(match.map((byte) => parseInt(byte, 16)));
}

export function isHexString(value, length) {
    if (typeof value !== "string" || !value.match(/^0x[0-9A-Fa-f]*$/g)) {
        return false;
    } else if (length && value.length !== 2 + 2 * length) {
        return false;
    }
    return true;
}

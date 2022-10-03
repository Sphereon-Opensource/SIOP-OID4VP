import { parse } from 'querystring';

import * as bs58 from 'bs58';
import * as u8a from 'uint8arrays';

import { SIOPErrors } from '../types';

export function bytesToHexString(bytes: Uint8Array): string {
  return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}

export function decodeUriAsJson(uri: string) {
  if (!uri || !uri.includes('openid')) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  }
  const parts = parse(uri);

  const json = {};
  for (const key in parts) {
    const value = parts[key];
    if (!value) {
      continue;
    }
    const isBool = typeof value == 'boolean';
    const isNumber = typeof value == 'number';
    const isString = typeof value == 'string';

    if (isBool || isNumber) {
      json[decodeURIComponent(key)] = value;
    } else if (isString) {
      const decoded = decodeURIComponent(value);
      if (decoded.startsWith('{') && decoded.endsWith('}')) {
        json[decodeURIComponent(key)] = JSON.parse(decoded);
      } else {
        json[decodeURIComponent(key)] = decoded;
      }
    }
  }
  return json;
}

export function encodeJsonAsURI(json: unknown) {
  if (typeof json === 'string') {
    return encodeJsonAsURI(JSON.parse(json));
  }

  const results = [];

  function encodeAndStripWhitespace(key: string) {
    return encodeURIComponent(key.replace(' ', ''));
  }

  for (const [key, value] of Object.entries(json)) {
    if (!value) {
      continue;
    }
    const isBool = typeof value == 'boolean';
    const isNumber = typeof value == 'number';
    const isString = typeof value == 'string';
    let encoded;
    if (isBool || isNumber) {
      encoded = `${encodeAndStripWhitespace(key)}=${value}`;
    } else if (isString) {
      encoded = `${encodeAndStripWhitespace(key)}=${encodeURIComponent(value)}`;
    } else {
      encoded = `${encodeAndStripWhitespace(key)}=${encodeURIComponent(JSON.stringify(value))}`;
    }
    results.push(encoded);
  }
  return results.join('&');
}

export function base64ToHexString(input: string): string {
  return Buffer.from(input, 'base64').toString('hex');
}

export function base64ToBytes(s: string): Uint8Array {
  const inputBase64Url = s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return u8a.fromString(inputBase64Url, 'base64url');
}

export function bytesFromHexString(hexString: string): Uint8Array {
  const match = hexString.match(/.{1,2}/g);
  if (!match) {
    throw new Error('String does not seem to be in HEX');
  }
  return new Uint8Array(match.map((byte) => parseInt(byte, 16)));
}

export function isHexString(value: string, length?: number): boolean {
  if (typeof value !== 'string' || !value.match(/^[0-9A-Fa-f]*$/g)) {
    return false;
  } else if (length && value.length !== 2 * length) {
    return false;
  }
  return true;
}

export function base58ToBase64String(base58: string): string {
  return Buffer.from(bs58.decode(base58)).toString('base64');
}

export function fromBase64(base64: string): string {
  return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

export function base64urlEncodeBuffer(buf: { toString: (arg0: 'base64') => string }): string {
  return fromBase64(buf.toString('base64'));
}

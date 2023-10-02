import { parse } from 'querystring';

import * as ua8 from 'uint8arrays';

import { SIOPErrors } from '../types';

export function decodeUriAsJson(uri: string) {
  if (!uri) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  }
  const queryString = uri.replace(/^([a-zA-Z][a-zA-Z0-9-_]*:\/\/[a-zA-Z0-9-_%:@\.~!$&'()*+,;=]*[?]?)/, '');
  if (!queryString) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  }
  const parts = parse(queryString);

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

export function encodeJsonAsURI(json: unknown): string {
  if (typeof json === 'string') {
    return encodeJsonAsURI(JSON.parse(json));
  }

  const results: string[] = [];

  function encodeAndStripWhitespace(key: string): string {
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

export function base64ToHexString(input: string, encoding?: 'base64url' | 'base64'): string {
  return ua8.toString(ua8.fromString(input, encoding ?? 'base64url'), 'base16');
}

export function fromBase64(base64: string): string {
  return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

export function base64urlEncodeBuffer(buf: { toString: (arg0: 'base64') => string }): string {
  return fromBase64(buf.toString('base64'));
}

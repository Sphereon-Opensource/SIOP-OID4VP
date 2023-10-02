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

function encodeAndStripWhitespace(key: string): string {
  return encodeURIComponent(key.replace(' ', ''));
}

export function encodeJsonAsURI(json: unknown, uriEncodedJsonProperties: string[] = []): string {
  let parsedJson = json;
  if (typeof parsedJson === 'string') {
    parsedJson = JSON.parse(parsedJson);
  }

  // If no custom properties, we can just encode everything
  if (uriEncodedJsonProperties.length === 0) {
    return encodeAsUriValue(undefined, json);
  }

  const results: string[] = [];

  for (const [key, value] of Object.entries(json)) {
    // Value of property must be seen as a separate uri encoded property.
    if (uriEncodedJsonProperties.includes(key)) {
      if (typeof value !== 'object' || Array.isArray(value) || value === null) {
        throw new Error('Cannot encode non-object value as URI encoded JSON property');
      }
      results.push(`${encodeAndStripWhitespace(key)}=${encodeURIComponent(encodeAsUriValue(undefined, value))}`);
    } else {
      results.push(encodeAsUriValue(key, value));
    }
  }
  return results.join('&');
}

export function encodeAsUriValue(key: string | undefined, value: unknown, base: string | undefined = undefined): string {
  const results: string[] = [];

  const isBool = typeof value == 'boolean';
  const isNumber = typeof value == 'number';
  const isString = typeof value == 'string';
  const isArray = Array.isArray(value);

  if (!key && !base && (isBool || isNumber || isString || isArray)) {
    throw new Error('Cannot encode value (boolean, string, number, array) without key or base');
  }

  let encodedKey: string | undefined = undefined;
  if (key && !base) {
    encodedKey = encodeAndStripWhitespace(key);
  } else if (key && base) {
    encodedKey = `${base}[${encodeAndStripWhitespace(key)}]`;
  } else if (!key && base) {
    encodedKey = base;
  }

  if (value === null || value === undefined) {
    throw new Error('Cannot encode null or undefined value');
  } else if (isBool || isNumber) {
    results.push(`${encodedKey}=${value}`);
  } else if (isString) {
    results.push(`${encodedKey}=${encodeURIComponent(value)}`);
  } else if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      results.push(
        encodeAsUriValue(
          undefined,
          entry,
          base ? `${base}[${encodeAndStripWhitespace(key)}][${index}]` : `${encodeAndStripWhitespace(key)}[${index}]`
        )
      );
    });
  } else if (typeof value === 'object') {
    for (const [subKey, subValue] of Object.entries(value)) {
      results.push(encodeAsUriValue(subKey, subValue, encodedKey));
    }
  } else {
    throw new Error('Unknown value type');
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

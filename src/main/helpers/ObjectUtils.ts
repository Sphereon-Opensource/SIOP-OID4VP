import jp from 'jsonpath';

export function extractDataFromPath(obj: unknown, path: string) {
  return jp.nodes(obj, path);
}

export function isStringNullOrEmpty(key: string) {
  return !key || !key.length;
}

import jp from 'jsonpath';

export function extractDataFromPath(obj: unknown, path: string) {
  return jp.nodes(obj, path);
}

export function isStringNullOrEmpty(key: string) {
  return !key || !key.length;
}

export function removeNullUndefined(data: unknown) {
  if (!data) {
    return data;
  }
  //transform properties into key-values pairs and filter all the empty-values
  const entries = Object.entries(data).filter(([, value]) => value != null);
  //map through all the remaining properties and check if the value is an object.
  //if value is object, use recursion to remove empty properties
  const clean = entries.map(([key, v]) => {
    const value = typeof v === 'object' && !Array.isArray(v) ? removeNullUndefined(v) : v;
    return [key, value];
  });
  //transform the key-value pairs back to an object.
  return Object.fromEntries(clean);
}
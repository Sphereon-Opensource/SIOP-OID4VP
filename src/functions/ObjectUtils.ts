import jp from 'jsonpath';

export function extractDataFromPath(obj: unknown, path: string) {
  return jp.nodes(obj, path);
}

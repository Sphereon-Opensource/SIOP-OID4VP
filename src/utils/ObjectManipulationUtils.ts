export class ObjectManipulationUtils {
  /**
   *  This method converts all the complex object to one-level complexity.
   *  If you have a nested object, this method will change the nested object to a simple string using JSON.stringify method
   *
   *  @param    {object}            object                any object that you need to flatten
   *  @return   {object}            flattened object
   */
  public static flattenObject(object) {
    const flattenedObj: any = { ...object };
    for (const [key, value] of Object.entries(object)) {
      const isBool = typeof value == 'boolean';
      const isNumber = typeof value == 'number';
      const isString = typeof value == 'string';
      if (!isBool && !isNumber && !isString) {
        flattenedObj[key] = JSON.stringify(value);
      }
    }
    return flattenedObj;
  }
}

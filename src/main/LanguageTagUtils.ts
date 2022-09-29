import Tags from 'language-tags';

import { SIOPErrors } from './types';

export default class LanguageTagUtils {
  private static readonly LANGUAGE_TAG_SEPARATOR = '#';

  static getLanguageTaggedProperties(source: any, languageTagEnabledFieldsNames: Array<string>): any {
    const languageTagEnabledFieldsNamesMapping: Map<string, string> = new Map<string, string>();
    languageTagEnabledFieldsNames.forEach((value) => languageTagEnabledFieldsNamesMapping.set(value, value));
    return this.getLanguageTaggedPropertiesMapped(source, languageTagEnabledFieldsNamesMapping);
  }

  static getLanguageTaggedPropertiesMapped(source: any, languageTagEnabledFieldsNamesMapping: Map<string, string>): any {
    this.assertSourceIsWorthChecking(source);
    this.assertValidTargetFieldNames(languageTagEnabledFieldsNamesMapping);

    const discoveredLanguageTaggedFields = [];

    Object.entries(source).forEach(([key, value]) => {
      const languageTagSeparatorIndexInKey = key.indexOf(this.LANGUAGE_TAG_SEPARATOR);

      if (this.isFieldLanguageTagged(languageTagSeparatorIndexInKey)) {
        this.extractLanguageTaggedField(key, value as string, languageTagSeparatorIndexInKey, languageTagEnabledFieldsNamesMapping, discoveredLanguageTaggedFields);
      }
    });

    return discoveredLanguageTaggedFields;
  }

  private static extractLanguageTaggedField(
    key: string,
    value: string,
    languageTagSeparatorIndexInKey: number,
    languageTagEnabledFieldsNamesMapping: Map<string, string>,
    languageTaggedFields: any[]
  ) {
    this.assertFieldNameShouldBeNonEmpty(key, languageTagSeparatorIndexInKey);
    const fieldName = this.getFieldName(key, languageTagSeparatorIndexInKey);
    if (languageTagEnabledFieldsNamesMapping.has(fieldName)) {
      const languageTag = this.getLanguageTag(key, languageTagSeparatorIndexInKey);
      if (Tags.check(languageTag)) {
        languageTaggedFields[this.getMappedFieldName(languageTagEnabledFieldsNamesMapping, fieldName, languageTag)] = value;
      }
    }
  }

  private static getMappedFieldName(languageTagEnabledFieldsNamesMapping: Map<string, string>, fieldName: string, languageTag: string) {
    return languageTagEnabledFieldsNamesMapping.get(fieldName) + '#' + languageTag;
  }

  private static getLanguageTag(key: string, languageTagSeparatorIndex: number) {
    return key.substring(languageTagSeparatorIndex + 1);
  }

  private static getFieldName(key: string, languageTagSeparatorIndex: number) {
    return key.substring(0, languageTagSeparatorIndex);
  }

  /***
   * This function checks about the field to be language-tagged.
   *
   * @param languageTagSeparatorIndex
   * @private
   */
  private static isFieldLanguageTagged(languageTagSeparatorIndex) {
    return languageTagSeparatorIndex > 0;
  }

  private static assertFieldNameShouldBeNonEmpty(key, languageTagSeparatorIndex) {
    if (languageTagSeparatorIndex < 1) {
      throw new Error(SIOPErrors.BAD_PARAMS + ' Field name not found in the key name: ' + key);
    }
  }

  private static assertValidTargetFieldNames(languageTagEnabledFieldsNamesMapping: Map<string, string>) {
    if (!languageTagEnabledFieldsNamesMapping?.size) {
      throw new Error(SIOPErrors.BAD_PARAMS + ' LanguageTagEnabledFieldsNamesMapping must be non-null or non-empty');
    } else {
      for (const entry of languageTagEnabledFieldsNamesMapping.entries()) {
        if (!entry[0]?.length || !entry[1]?.length) {
          throw new Error(SIOPErrors.BAD_PARAMS + '. languageTagEnabledFieldsName must be non-null or non-empty');
        }
      }
    }
  }

  private static assertSourceIsWorthChecking(source: any) {
    if (!source) {
      throw new Error(SIOPErrors.BAD_PARAMS + ' Source must be non-null i.e. not-initialized.');
    }
  }
}

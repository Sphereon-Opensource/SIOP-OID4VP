import Tags from 'language-tags';

import { SIOPErrors } from './types';

export default class LanguageTagUtils {
  private static readonly LANGUAGE_TAG_SEPARATOR = '#';

  static getLanguageTaggedProperties(source: any, targetFieldNames: Array<string>): any {
    const targetFieldNamesMap: Map<string, string> = new Map<string, string>();
    targetFieldNames.forEach((value) => targetFieldNamesMap.set(value, value));
    return this.getLanguageTaggedPropertiesMapped(source, targetFieldNamesMap);
  }

  static getLanguageTaggedPropertiesMapped(source: any, targetFieldNames: Map<string, string>): any {
    this.assertSourceIsWorthChecking(source);
    this.assertValidTargetFieldNames(targetFieldNames);

    const languageTaggedFields = [];

    Object.entries(source).forEach(([key, value]) => {
      const languageTagSeparatorIndex = key.indexOf(this.LANGUAGE_TAG_SEPARATOR);

      if (this.isFieldLanguageTagged(languageTagSeparatorIndex)) {
        this.extractLanguageTaggedField(languageTaggedFields, targetFieldNames, key, value as string, languageTagSeparatorIndex);
      }
    });

    return languageTaggedFields;
  }

  private static extractLanguageTaggedField(
    languageTaggedFields: any[],
    targetFieldNames: Map<string, string>,
    key: string,
    value: string,
    languageTagSeparatorIndex: number
  ) {
    this.assertFieldNameShouldBeNonEmpty(key, languageTagSeparatorIndex);
    const fieldName = this.getFieldName(key, languageTagSeparatorIndex);
    if (targetFieldNames.has(fieldName)) {
      const languageTag = this.getLanguageTag(key, languageTagSeparatorIndex);
      if (Tags.check(languageTag)) {
        languageTaggedFields[this.getMappedFieldName(targetFieldNames, fieldName, languageTag)] = value;
      }
    }
  }

  private static getMappedFieldName(targetFieldNames: Map<string, string>, fieldName: string, languageTag: string) {
    return targetFieldNames.get(fieldName) + '#' + languageTag;
  }

  private static getLanguageTag(key: string, languageTagSeparatorIndex: number) {
    return key.substring(languageTagSeparatorIndex + 1);
  }

  private static getFieldName(key: string, languageTagSeparatorIndex: number) {
    return key.substring(0, languageTagSeparatorIndex);
  }

  private static isFieldLanguageTagged(languageTagSeparatorIndex) {
    return languageTagSeparatorIndex > 0;
  }

  private static assertFieldNameShouldBeNonEmpty(key, languageTagSeparatorIndex) {
    if (languageTagSeparatorIndex < 1) {
      throw new Error(SIOPErrors.BAD_PARAMS + ' field name not found in the key name: ' + key);
    }
  }

  private static assertValidTargetFieldNames(targetFieldNames: Map<string, string>) {
    if (!targetFieldNames?.size) {
      throw new Error(SIOPErrors.BAD_PARAMS + ' targetFieldNames is null or empty');
    } else {
      for (const entry of targetFieldNames.entries()) {
        if (!entry[0]?.length || !entry[1]?.length) {
          throw new Error(SIOPErrors.BAD_PARAMS);
        }
      }
    }
  }

  private static assertSourceIsWorthChecking(source: any) {
    if (!source) {
      throw new Error(SIOPErrors.BAD_PARAMS + ' Source must be non-null i.e. initialized.');
    }
  }
}

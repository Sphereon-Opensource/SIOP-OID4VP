import Tags from 'language-tags';

import { SIOPErrors } from './types';

export default class LanguageTagUtils {
  private static readonly LANGUAGE_TAG_SEPARATOR = '#';

  static getAllLanguageTaggedProperties(source: unknown): Map<string, string> {
    return this.getLanguageTaggedPropertiesMapped(source, undefined);
  }

  static getLanguageTaggedProperties(source: unknown, languageTagEnabledFieldsNames: Array<string>): Map<string, string> {
    const languageTagEnabledFieldsNamesMapping: Map<string, string> = new Map<string, string>();
    languageTagEnabledFieldsNames.forEach((value) => languageTagEnabledFieldsNamesMapping.set(value, value));
    return this.getLanguageTaggedPropertiesMapped(source, languageTagEnabledFieldsNamesMapping);
  }

  static getLanguageTaggedPropertiesMapped(source: unknown, languageTagEnabledFieldsNamesMapping: Map<string, string>): Map<string, string> {
    this.assertSourceIsWorthChecking(source);
    this.assertValidTargetFieldNames(languageTagEnabledFieldsNamesMapping);

    const discoveredLanguageTaggedFields: Map<string, string> = new Map<string, string>();

    Object.entries(source).forEach(([key, value]) => {
      const languageTagSeparatorIndexInKey = key.indexOf(this.LANGUAGE_TAG_SEPARATOR);

      if (this.isFieldLanguageTagged(languageTagSeparatorIndexInKey)) {
        this.extractLanguageTaggedField(
          key,
          value as string,
          languageTagSeparatorIndexInKey,
          languageTagEnabledFieldsNamesMapping,
          discoveredLanguageTaggedFields
        );
      }
    });

    return discoveredLanguageTaggedFields;
  }

  private static extractLanguageTaggedField(
    key: string,
    value: string,
    languageTagSeparatorIndexInKey: number,
    languageTagEnabledFieldsNamesMapping: Map<string, string>,
    languageTaggedFields: Map<string, string>
  ) {
    const fieldName = this.getFieldName(key, languageTagSeparatorIndexInKey);

    const languageTag = this.getLanguageTag(key, languageTagSeparatorIndexInKey);
    if (Tags.check(languageTag)) {
      if (languageTagEnabledFieldsNamesMapping?.size) {
        if (languageTagEnabledFieldsNamesMapping.has(fieldName)) {
          languageTaggedFields.set(this.getMappedFieldName(languageTagEnabledFieldsNamesMapping, fieldName, languageTag), value);
        }
      } else {
        languageTaggedFields.set(key, value);
      }
    }
  }

  private static getMappedFieldName(languageTagEnabledFieldsNamesMapping: Map<string, string>, fieldName: string, languageTag: string) {
    return languageTagEnabledFieldsNamesMapping.get(fieldName) + this.LANGUAGE_TAG_SEPARATOR + languageTag;
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

  private static assertValidTargetFieldNames(languageTagEnabledFieldsNamesMapping: Map<string, string>) {
    if (languageTagEnabledFieldsNamesMapping) {
      if (!languageTagEnabledFieldsNamesMapping.size) {
        throw new Error(SIOPErrors.BAD_PARAMS + ' LanguageTagEnabledFieldsNamesMapping must be non-null or non-empty');
      } else {
        for (const entry of languageTagEnabledFieldsNamesMapping.entries()) {
          const key = entry[0];
          const value = entry[1];
          if (this.isStringNullOrEmpty(key) || this.isStringNullOrEmpty(value)) {
            throw new Error(SIOPErrors.BAD_PARAMS + '. languageTagEnabledFieldsName must be non-null or non-empty');
          }
        }
      }
    }
  }

  private static isStringNullOrEmpty(key: string) {
    return !key || !key.length;
  }

  private static assertSourceIsWorthChecking(source: unknown) {
    if (!source) {
      throw new Error(SIOPErrors.BAD_PARAMS + ' Source must be non-null i.e. not-initialized.');
    }
  }
}

import { EvaluationResults, PEJS, SelectResults, VerifiablePresentation } from '@sphereon/pe-js';
import { VerifiableCredential } from '@sphereon/pe-js/lib/verifiablePresentation/index';
import { PresentationDefinition, PresentationSubmission } from '@sphereon/pe-models';

import { extractDataFromPath } from './functions/ObjectUtils';
import { SIOPErrors } from './types';

export class PEManager {
  // We update this if necessary
  pejs: PEJS = new PEJS();

  public evaluate(
    presentationDefinition: PresentationDefinition,
    verifiablePresentation: VerifiablePresentation
  ): EvaluationResults {
    this.pejs = new PEJS();
    return this.pejs.evaluate(presentationDefinition, verifiablePresentation);
  }

  public submissionFrom(
    presentationDefinition: PresentationDefinition,
    verifiableCredential: VerifiableCredential[]
  ): PresentationSubmission {
    return this.pejs.submissionFrom(presentationDefinition, verifiableCredential);
  }

  public selectFrom(
    presentationDefinition: PresentationDefinition,
    selectedCredentials: VerifiableCredential[],
    holderDid: string
  ): SelectResults {
    this.pejs = new PEJS();
    return this.pejs.selectFrom(presentationDefinition, selectedCredentials, holderDid);
  }

  private validatePresentationDefinition(presentationDefinition: PresentationDefinition) {
    const validationResult = this.pejs.validateDefinition(presentationDefinition);
    if (validationResult[0].message != 'ok') {
      throw new Error(`${SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID}`);
    }
  }

  /**
   * Finds a valid PresentationDefinition inside the given object
   * throws exception if the PresentationDefinition is not valid
   * returns null if no property named "presentation_definition" is found
   * returns a PresentationDefinition if a valid instance found
   * @param obj
   */
  public findValidPresentationDefinition(obj: unknown) {
    const optionalPD = extractDataFromPath(obj, '$..presentation_definition');
    if (optionalPD && optionalPD.length) {
      this.validatePresentationDefinition(optionalPD[0].value);
      return optionalPD[0].value;
    }
    return null;
  }
}

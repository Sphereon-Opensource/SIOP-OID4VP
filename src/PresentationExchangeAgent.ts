import { EvaluationResults, PEJS, SelectResults, Validated } from '@sphereon/pe-js';
import { VerifiableCredential, VerifiablePresentation } from '@sphereon/pe-js/lib/verifiablePresentation/index';
import { PresentationDefinition, PresentationSubmission } from '@sphereon/pe-models';

import { extractDataFromPath } from './functions/ObjectUtils';
import { SIOPErrors } from './types';

export class PresentationExchangeAgent {
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

  public validatePresentationDefinition(presentationDefinition: PresentationDefinition) {
    const validationResult = this.pejs.validateDefinition(presentationDefinition);
    if (validationResult[0].message != 'ok') {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
    }
  }

  public validatePresentationSubmission(presentationSubmission: PresentationSubmission): Validated {
    return this.pejs.validateSubmission(presentationSubmission);
  }

  public findValidPresentationDefinition(obj: unknown, path: string) {
    const optionalPD = extractDataFromPath(obj, path);
    if (optionalPD && optionalPD.length) {
      this.validatePresentationDefinition(optionalPD[0].value);
      return optionalPD[0].value;
    }
    return null;
  }
}

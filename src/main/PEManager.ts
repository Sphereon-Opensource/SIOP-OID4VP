import { EvaluationResults, PEJS, SelectResults, VerifiablePresentation } from '@sphereon/pe-js';
import { VerifiableCredential } from '@sphereon/pe-js/lib/verifiablePresentation/index';
import { PresentationDefinition, PresentationSubmission } from '@sphereon/pe-models';

import { extractDataFromPath } from './functions/ObjectUtils';
import { SIOP, SIOPErrors } from './types';

export class PEManager {
  pejs: PEJS = new PEJS();

  //TODO: from a procedural pov, RP already has the requestPayload object (containing the PD)
  // and it's better from a security pov that we don't get the presentationDefinition from OP
  /**
   * evaluate function is called mainly by the RP
   * after receiving the VP from the OP
   * @param requestPayload: payload object created by the RP
   * @param verifiablePresentation:
   */
  public evaluate(
    requestPayload: SIOP.AuthenticationRequestPayload,
    verifiablePresentation: VerifiablePresentation
  ): EvaluationResults {
    this.pejs = new PEJS();
    const presentationDefinition = this.findValidPresentationDefinition(requestPayload);
    if (!presentationDefinition) {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
    }
    return this.pejs.evaluate(presentationDefinition, verifiablePresentation);
  }

  /**
   * Construct presentation submission from selected credentials
   * @param requestPayload: payload object received by the OP from the RP
   * @param selectedCredentials
   */
  public submissionFrom(
    requestPayload: SIOP.AuthenticationRequestPayload,
    selectedCredentials: VerifiableCredential[]
  ): PresentationSubmission {
    const presentationDefinition = this.findValidPresentationDefinition(requestPayload);
    if (!presentationDefinition) {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
    }
    return this.pejs.submissionFrom(presentationDefinition, selectedCredentials);
  }

  /**
   * This method will be called from the OP when we are certain that we have a
   * PresentationDefinition object inside our requestPayload
   * Finds a set of `VerifiableCredential`s from a list provided by the OP,
   * matching presentationDefinition object found in the requestPayload
   * if requestPayload doesn't contain any valid presentationDefinition throws an error
   * if PE-JS library returns any error in the process, throws the error
   * returns the SelectResults object if successful
   * @param requestPayload: payload object received by the OP from the RP
   * @param credentials: a set of VCs that user selects in response to the given PD
   * @param holderDid: did of the holder related to this presentationDefinition
   */
  public selectVerifiableCredentialsForSubmission(
    requestPayload: SIOP.AuthenticationRequestPayload,
    credentials: VerifiableCredential[],
    holderDid: string
  ): SelectResults {
    const presentationDefinition = this.findValidPresentationDefinition(requestPayload);
    if (!presentationDefinition) {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
    }
    this.pejs = new PEJS();
    const selectResults: SelectResults = this.pejs.selectFrom(presentationDefinition, credentials, holderDid);
    if (selectResults.errors.length) {
      throw new Error(
        `message: ${SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, details: ${JSON.stringify(selectResults.errors)}`
      );
    }
    return selectResults;
  }

  private validatePresentationDefinition(presentationDefinition: PresentationDefinition) {
    const validationResult = this.pejs.validateDefinition(presentationDefinition);
    if (validationResult[0].message != 'ok') {
      throw new Error(`${SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID}`);
    }
  }

  /**
   * Finds a valid PresentationDefinition inside the given AuthenticationRequestPayload
   * throws exception if the PresentationDefinition is not valid
   * returns null if no property named "presentation_definition" is found
   * returns a PresentationDefinition if a valid instance found
   * @param requestPayload
   */
  public findValidPresentationDefinition(requestPayload: SIOP.AuthenticationRequestPayload) {
    const optionalPD = extractDataFromPath(requestPayload, '$..presentation_definition');
    if (optionalPD && optionalPD.length) {
      this.validatePresentationDefinition(optionalPD[0].value);
      return optionalPD[0].value;
    }
    return null;
  }
}

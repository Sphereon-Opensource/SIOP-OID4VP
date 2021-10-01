import { EvaluationResults, PEJS, Presentation, SelectResults, VerifiablePresentation, VP } from '@sphereon/pe-js';
import { VerifiableCredential } from '@sphereon/pe-js/lib/verifiablePresentation/index';
import { PresentationDefinition, PresentationSubmission } from '@sphereon/pe-models';

import { extractDataFromPath } from './functions/ObjectUtils';
import { SIOP, SIOPErrors } from './types';

export class PEManager {
  // todo ensure we set the VCs only once and not reinitialize pejs every time
  pejs: PEJS = new PEJS();

  //TODO: from a procedural pov, RP already has the requestPayload object (containing the PD)
  // and it's better from a security pov that we don't get the presentationDefinition from OP
  /**
   * evaluate function is called mainly by the RP
   * after receiving the VP from the OP
   * @param verifiedJwt: object containing PD
   * @param verifiablePresentation:
   */
  public static async evaluate(
    verifiedJwt: SIOP.VerifiedAuthenticationRequestWithJWT,
    verifiablePresentation: VerifiablePresentation
  ): Promise<EvaluationResults> {
    if (!verifiedJwt || !verifiedJwt.presentationDefinition) {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
    }
    const evaluationResults: EvaluationResults = new PEJS().evaluate(
      verifiedJwt.presentationDefinition,
      verifiablePresentation
    );
    if (evaluationResults.errors.length) {
      throw new Error(
        `message: ${SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, details: ${JSON.stringify(evaluationResults.errors)}`
      );
    }
    return evaluationResults;
  }

  /**
   * Construct presentation submission from selected credentials
   * @param verifiedJwt: payload object received by the OP from the RP
   * @param selectedCredentials
   */
  public async submissionFrom(
    verifiedJwt: SIOP.VerifiedAuthenticationRequestWithJWT,
    selectedCredentials: VerifiableCredential[],
    holderDid: string
  ): Promise<VerifiablePresentation> {
    const presentationDefinition = PEManager.findValidPresentationDefinition(verifiedJwt);
    if (!presentationDefinition) {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
    }
    const ps: PresentationSubmission = this.pejs.submissionFrom(presentationDefinition, selectedCredentials);
    return new VP(new Presentation(null, ps, ['verifiableCredential'], selectedCredentials, holderDid, null));
  }

  /**
   * This method will be called from the OP when we are certain that we have a
   * PresentationDefinition object inside our requestPayload
   * Finds a set of `VerifiableCredential`s from a list provided by the OP,
   * matching presentationDefinition object found in the requestPayload
   * if requestPayload doesn't contain any valid presentationDefinition throws an error
   * if PE-JS library returns any error in the process, throws the error
   * returns the SelectResults object if successful
   * @param verifiedJwt: object received by the OP from the RP
   * @param credentials: a set of VCs that user selects in response to the given PD
   */
  public async selectVerifiableCredentialsForSubmission(
    verifiedJwt: SIOP.VerifiedAuthenticationRequestWithJWT,
    credentials: VerifiableCredential[],
    holderDid: string
  ): Promise<SelectResults> {
    const presentationDefinition = PEManager.findValidPresentationDefinition(verifiedJwt.payload);
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

  private static validatePresentationDefinition(presentationDefinition: PresentationDefinition) {
    const validationResult = new PEJS().validateDefinition(presentationDefinition);
    if (validationResult[0].message != 'ok') {
      throw new Error(`${SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID}`);
    }
  }

  public static validatePresentationSubmission(presentationSubmission: PresentationSubmission) {
    const validationResult = new PEJS().validateSubmission(presentationSubmission);
    if (validationResult[0].message != 'ok') {
      throw new Error(`${SIOPErrors.RESPONSE_OPTS_PRESENTATIONS_SUBMISSION_IS_NOT_VALID}`);
    }
  }

  /**
   * Finds a valid PresentationDefinition inside the given AuthenticationRequestPayload
   * throws exception if the PresentationDefinition is not valid
   * returns null if no property named "presentation_definition" is found
   * returns a PresentationDefinition if a valid instance found
   * @param obj: object that can have a presentation_definition inside
   */
  public static findValidPresentationDefinition(obj: unknown) {
    const optionalPD = extractDataFromPath(obj, '$..presentation_definition');
    if (optionalPD && optionalPD.length) {
      PEManager.validatePresentationDefinition(optionalPD[0].value);
      return optionalPD[0].value;
    }
    return null;
  }
}

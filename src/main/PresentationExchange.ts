import {
  EvaluationResults,
  KeyEncoding,
  pejs,
  Presentation,
  PresentationSignCallBackParams,
  PresentationSignOptions,
  ProofPurpose,
  ProofType,
  SelectResults,
  VerifiableCredential,
  VerifiablePresentation,
} from '@sphereon/pe-js';
import { PresentationDefinition, PresentationSubmission } from '@sphereon/pe-models';

import { extractDataFromPath } from './functions/ObjectUtils';
import { SIOPErrors } from './types';
import { JWTPayload } from './types/JWT.types';
import {
  PresentationDefinitionWithLocation,
  PresentationLocation,
  VerifiablePresentationPayload,
  VerifiablePresentationTypeFormat,
} from './types/SIOP.types';

export class PresentationExchange {
  readonly pejs = new pejs();
  readonly allVerifiableCredentials: VerifiableCredential[];
  readonly did;

  constructor(opts: { did: string; allVerifiableCredentials: VerifiableCredential[] }) {
    this.did = opts.did;
    this.allVerifiableCredentials = opts.allVerifiableCredentials;
  }

  /**
   * Construct presentation submission from selected credentials
   * @param presentationDefinition: payload object received by the OP from the RP
   * @param selectedCredentials
   */
  public async submissionFrom(
    presentationDefinition: PresentationDefinition,
    selectedCredentials: VerifiableCredential[],
    options?: { nonce?: string; domain?: string }
  ): Promise<VerifiablePresentation> {
    if (!presentationDefinition) {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
    }

    function sign(params: PresentationSignCallBackParams): VerifiablePresentation {
      console.log('##### SIGN CALLBACK IMPLEMENTATION NEEDED FOR VP');
      console.log(params);
      return params.presentation as VerifiablePresentation;
    }

    const challenge: string = options?.nonce;
    const domain: string = options?.domain;

    // fixme: this needs to be configurable
    const signOptions: PresentationSignOptions = {
      proofOptions: {
        proofPurpose: ProofPurpose.authentication,
        type: ProofType.EcdsaSecp256k1Signature2019,
        challenge,
        domain,
      },
      signatureOptions: {
        verificationMethod: `${this.did}#key`,
        keyEncoding: KeyEncoding.Hex,
      },
    };

    return this.pejs.verifiablePresentationFrom(presentationDefinition, selectedCredentials, sign, signOptions);
  }

  /**
   * This method will be called from the OP when we are certain that we have a
   * PresentationDefinition object inside our requestPayload
   * Finds a set of `VerifiableCredential`s from a list supplied to this class during construction,
   * matching presentationDefinition object found in the requestPayload
   * if requestPayload doesn't contain any valid presentationDefinition throws an error
   * if PE-JS library returns any error in the process, throws the error
   * returns the SelectResults object if successful
   * @param presentationDefinition: object received by the OP from the RP
   */
  public async selectVerifiableCredentialsForSubmission(presentationDefinition: PresentationDefinition): Promise<SelectResults> {
    if (!presentationDefinition) {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
    } else if (!this.allVerifiableCredentials || this.allVerifiableCredentials.length == 0) {
      throw new Error(`${SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, no VCs were provided`);
    }
    const selectResults: SelectResults = this.pejs.selectFrom(
      presentationDefinition,
      // fixme holder dids and limited disclosure
      this.allVerifiableCredentials,
      [this.did],
      []
    );
    if (selectResults.errors.length) {
      throw new Error(`message: ${SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, details: ${JSON.stringify(selectResults.errors)}`);
    }
    return selectResults;
  }

  /**
   * validatePresentationAgainstDefinition function is called mainly by the RP
   * after receiving the VP from the OP
   * @param presentationDefinition: object containing PD
   * @param verifiablePresentation:
   */
  public static async validatePresentationAgainstDefinition(
    presentationDefinition: PresentationDefinition,
    verifiablePresentation: Presentation
  ): Promise<EvaluationResults> {
    if (!presentationDefinition) {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
    }
    const evaluationResults: EvaluationResults = new pejs().evaluatePresentation(presentationDefinition, verifiablePresentation);
    if (evaluationResults.errors.length) {
      throw new Error(`message: ${SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, details: ${JSON.stringify(evaluationResults.errors)}`);
    }
    return evaluationResults;
  }

  public static assertValidPresentationSubmission(presentationSubmission: PresentationSubmission) {
    const validationResult = new pejs().validateSubmission(presentationSubmission);
    if (validationResult[0].message != 'ok') {
      throw new Error(`${SIOPErrors.RESPONSE_OPTS_PRESENTATIONS_SUBMISSION_IS_NOT_VALID}, details ${JSON.stringify(validationResult[0])}`);
    }
  }

  /**
   * Finds a valid PresentationDefinition inside the given AuthenticationRequestPayload
   * throws exception if the PresentationDefinition is not valid
   * returns null if no property named "presentation_definition" is found
   * returns a PresentationDefinition if a valid instance found
   * @param obj: object that can have a presentation_definition inside
   */
  public static findValidPresentationDefinitions(obj: JWTPayload): PresentationDefinitionWithLocation[] {
    let allDefinitions: PresentationDefinitionWithLocation[];

    function extractPDFromVPToken() {
      const vpTokens = extractDataFromPath(obj, '$..vp_token.presentation_definition');

      if (vpTokens) {
        if (vpTokens.length == 1) {
          PresentationExchange.assertValidPresentationDefinition(vpTokens[0].value);
          allDefinitions = [{ definition: vpTokens[0].value, location: PresentationLocation.VP_TOKEN }];
        } else if (vpTokens.length > 1) throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
      }
    }

    function extractPDFromOtherTokens() {
      const definitions = extractDataFromPath(obj, '$..verifiable_presentations.presentation_definition');
      if (definitions && definitions.length) {
        definitions.forEach((definition) => {
          PresentationExchange.assertValidPresentationDefinition(definition.value);
          if (definition.path.includes(PresentationLocation.ID_TOKEN)) {
            const defWithLocation = { definition: definition.value, location: PresentationLocation.ID_TOKEN };
            if (!allDefinitions) {
              allDefinitions = [defWithLocation];
            } else {
              allDefinitions.push(defWithLocation);
            }
          } else {
            throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
          }
        });
      }
    }

    if (obj) {
      extractPDFromVPToken();
      extractPDFromOtherTokens();
    }
    return allDefinitions;
  }

  public static assertValidPresentationDefintionWithLocations(defintionWithLocations: PresentationDefinitionWithLocation[]) {
    if (defintionWithLocations && defintionWithLocations.length > 0) {
      defintionWithLocations.forEach((definitionWithLocation) =>
        PresentationExchange.assertValidPresentationDefinition(definitionWithLocation.definition)
      );
    }
  }

  public static assertValidPresentationDefintionWithLocation(defintionWithLocation: PresentationDefinitionWithLocation) {
    if (defintionWithLocation && defintionWithLocation.definition) {
      PresentationExchange.assertValidPresentationDefinition(defintionWithLocation.definition);
    }
  }

  private static assertValidPresentationDefinition(presentationDefinition: PresentationDefinition) {
    const validationResult = new pejs().validateDefinition(presentationDefinition);
    if (validationResult[0].message != 'ok') {
      throw new Error(`${SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID}`);
    }
  }

  static async validatePayloadsAgainstDefinitions(definitions: PresentationDefinitionWithLocation[], vpPayloads: VerifiablePresentationPayload[]) {
    if (!definitions || !vpPayloads || !definitions.length || definitions.length !== vpPayloads.length) {
      throw new Error(SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD);
    }
    await Promise.all(definitions.map(async (pd) => await PresentationExchange.validatePayloadAgainstDefinitions(pd.definition, vpPayloads)));
  }

  private static async validatePayloadAgainstDefinitions(definition: PresentationDefinition, vpPayloads: VerifiablePresentationPayload[]) {
    function filterValidPresentations() {
      const checkedPresentations: VerifiablePresentationPayload[] = vpPayloads.filter((vpw) => {
        if (vpw.format !== VerifiablePresentationTypeFormat.LDP_VP) {
          throw new Error(`${SIOPErrors.VERIFIABLE_PRESENTATION_FORMAT_NOT_SUPPORTED}`);
        }

        const presentation = vpw.presentation;
        // fixme: Limited disclosure suites
        const evaluationResults = new pejs().evaluatePresentation(definition, presentation, []);
        const submission = evaluationResults.value;
        if (!presentation || !submission) {
          throw new Error(SIOPErrors.NO_PRESENTATION_SUBMISSION);
        }
        return submission && submission.definition_id === definition.id;
      });
      return checkedPresentations;
    }

    const checkedPresentations: VerifiablePresentationPayload[] = filterValidPresentations();

    if (!checkedPresentations.length || checkedPresentations.length != 1) {
      throw new Error(`${SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}`);
    } else if (checkedPresentations[0].format !== VerifiablePresentationTypeFormat.LDP_VP) {
      throw new Error(`${SIOPErrors.VERIFIABLE_PRESENTATION_FORMAT_NOT_SUPPORTED}`);
    }
    const presentation: Presentation = checkedPresentations[0].presentation;
    // fixme: Limited disclosure suites
    const evaluationResults = new pejs().evaluatePresentation(definition, presentation, []);
    PresentationExchange.assertValidPresentationSubmission(evaluationResults.value);
    await PresentationExchange.validatePresentationAgainstDefinition(definition, presentation);
  }
}

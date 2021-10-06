import { EvaluationResults, PEJS, Presentation, SelectResults, VerifiablePresentation, VP } from '@sphereon/pe-js';
import { VerifiableCredential } from '@sphereon/pe-js/lib/verifiablePresentation/index';
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
  readonly pejs: PEJS = new PEJS();
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
    selectedCredentials: VerifiableCredential[]
  ): Promise<VerifiablePresentation> {
    if (!presentationDefinition) {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
    }
    const ps: PresentationSubmission = this.pejs.submissionFrom(presentationDefinition, selectedCredentials);
    return new VP(new Presentation(null, ps, ['verifiableCredential'], selectedCredentials, this.did, null));
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
  public async selectVerifiableCredentialsForSubmission(
    presentationDefinition: PresentationDefinition
  ): Promise<SelectResults> {
    if (!presentationDefinition) {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
    }
    const selectResults: SelectResults = this.pejs.selectFrom(
      presentationDefinition,
      this.allVerifiableCredentials,
      this.did
    );
    if (selectResults.errors.length) {
      throw new Error(
        `message: ${SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, details: ${JSON.stringify(selectResults.errors)}`
      );
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
    verifiablePresentation: VerifiablePresentation
  ): Promise<EvaluationResults> {
    if (!presentationDefinition) {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
    }
    const evaluationResults: EvaluationResults = new PEJS().evaluate(presentationDefinition, verifiablePresentation);
    if (evaluationResults.errors.length) {
      throw new Error(
        `message: ${SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, details: ${JSON.stringify(evaluationResults.errors)}`
      );
    }
    return evaluationResults;
  }

  public static assertValidPresentationSubmission(presentationSubmission: PresentationSubmission) {
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
  public static findValidPresentationDefinitions(obj: JWTPayload): PresentationDefinitionWithLocation[] {
    if (obj) {
      const definitions = extractDataFromPath(obj, "$..['presentation_definition','presentation_definitions']");
      if (definitions && definitions.length) {
        return definitions.map((definition) => {
          PresentationExchange.assertValidPresentationDefinition(definition.value);
          let location;
          if (definition.path.includes(PresentationLocation.ID_TOKEN)) {
            location = PresentationLocation.ID_TOKEN;
          } else if (definition.path.includes(PresentationLocation.VP_TOKEN)) {
            location = PresentationLocation.VP_TOKEN;
          } else {
            throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
          }
          const result: PresentationDefinitionWithLocation = { definition, location };
          return result;
        });
      }
    }
    return null;
  }

  public static assertValidPresentationDefintionWithLocations(
    defintionWithLocations: PresentationDefinitionWithLocation[]
  ) {
    if (defintionWithLocations && defintionWithLocations.length > 0) {
      defintionWithLocations.forEach((definitionWithLocation) =>
        PresentationExchange.assertValidPresentationDefinition(definitionWithLocation.definition)
      );
    }
  }

  public static assertValidPresentationDefintionWithLocation(
    defintionWithLocation: PresentationDefinitionWithLocation
  ) {
    if (defintionWithLocation && defintionWithLocation.definition) {
      PresentationExchange.assertValidPresentationDefinition(defintionWithLocation.definition);
    }
  }

  private static assertValidPresentationDefinition(presentationDefinition: PresentationDefinition) {
    const validationResult = new PEJS().validateDefinition(presentationDefinition);
    if (validationResult[0].message != 'ok') {
      throw new Error(`${SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID}`);
    }
  }

  static async validatePayloadsAgainstDefinitions(
    definitions: PresentationDefinitionWithLocation[],
    vpPayloads: VerifiablePresentationPayload[]
  ) {
    if (!definitions || !vpPayloads || !definitions.length || definitions.length !== vpPayloads.length) {
      throw new Error(SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD);
    }
    await Promise.all(
      definitions.map(async (pd) => PresentationExchange.validatePayloadAgainstDefinitions(pd.definition, vpPayloads))
    );
  }

  private static async validatePayloadAgainstDefinitions(
    definition: PresentationDefinition,
    vpPayloads: VerifiablePresentationPayload[]
  ) {
    const fiVpws: VerifiablePresentationPayload[] = vpPayloads.filter((vpw) => {
      if (vpw.format !== VerifiablePresentationTypeFormat.LDP_VP) {
        throw new Error(`${SIOPErrors.VERIFIABLE_PRESENTATION_FORMAT_NOT_SUPPORTED}`);
      }
      const vp: VerifiablePresentation = new VP(<Presentation>vpw.presentation);

      return vp.getPresentationSubmission().definition_id === definition.id;
    });
    if (!fiVpws.length || fiVpws.length != 1) {
      throw new Error(`${SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}`);
    } else if (fiVpws[0].format !== VerifiablePresentationTypeFormat.LDP_VP) {
      throw new Error(`${SIOPErrors.VERIFIABLE_PRESENTATION_FORMAT_NOT_SUPPORTED}`);
    }
    const vp: VerifiablePresentation = new VP(<Presentation>fiVpws[0].presentation);
    PresentationExchange.assertValidPresentationSubmission(vp.getPresentationSubmission());
    await PresentationExchange.validatePresentationAgainstDefinition(definition, vp);
  }
}

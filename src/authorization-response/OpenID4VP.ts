import { IPresentationDefinition, PEX } from '@sphereon/pex';
import { Format } from '@sphereon/pex-models';
import { CredentialMapper, Hasher, PresentationSubmission, W3CVerifiablePresentation, WrappedVerifiablePresentation } from '@sphereon/ssi-types';

import { AuthorizationRequest } from '../authorization-request';
import { verifyRevocation } from '../helpers';
import {
  AuthorizationResponsePayload,
  IDTokenPayload,
  ResponseType,
  RevocationVerification,
  SIOPErrors,
  SupportedVersion,
  VerifiedOpenID4VPSubmission,
} from '../types';

import { AuthorizationResponse } from './AuthorizationResponse';
import { PresentationExchange } from './PresentationExchange';
import {
  AuthorizationResponseOpts,
  PresentationDefinitionWithLocation,
  PresentationVerificationCallback,
  VerifyAuthorizationResponseOpts,
  VPTokenLocation,
} from './types';

export const verifyPresentations = async (
  authorizationResponse: AuthorizationResponse,
  verifyOpts: VerifyAuthorizationResponseOpts
): Promise<VerifiedOpenID4VPSubmission> => {
  const presentations = await extractPresentationsFromAuthorizationResponse(authorizationResponse, { hasher: verifyOpts.hasher });
  const presentationDefinitions = verifyOpts.presentationDefinitions
    ? Array.isArray(verifyOpts.presentationDefinitions)
      ? verifyOpts.presentationDefinitions
      : [verifyOpts.presentationDefinitions]
    : [];
  let idPayload: IDTokenPayload | undefined;
  if (authorizationResponse.idToken) {
    idPayload = await authorizationResponse.idToken.payload();
  }
  // todo: Probably wise to check against request for the location of the submission_data
  const presentationSubmission = idPayload?._vp_token?.presentation_submission ?? authorizationResponse.payload.presentation_submission;

  await assertValidVerifiablePresentations({
    presentationDefinitions,
    presentations,
    verificationCallback: verifyOpts.verification.presentationVerificationCallback,
    opts: {
      presentationSubmission,
      restrictToFormats: verifyOpts.restrictToFormats,
      restrictToDIDMethods: verifyOpts.restrictToDIDMethods,
      hasher: verifyOpts.hasher,
    },
  });

  const nonces: Set<string> = new Set(presentations.map((presentation) => presentation.decoded.nonce));
  if (presentations.length > 0 && nonces.size !== 1) {
    throw Error(`${nonces.size} nonce values found for ${presentations.length}. Should be 1`);
  }

  const nonce = nonces[0];

  const revocationVerification = verifyOpts.verification?.revocationOpts
    ? verifyOpts.verification.revocationOpts.revocationVerification
    : RevocationVerification.IF_PRESENT;
  if (revocationVerification !== RevocationVerification.NEVER) {
    if (!verifyOpts.verification.revocationOpts?.revocationVerificationCallback) {
      throw Error(`Please provide a revocation callback as revocation checking of credentials and presentations is not disabled`);
    }
    for (const vp of presentations) {
      await verifyRevocation(vp, verifyOpts.verification.revocationOpts.revocationVerificationCallback, revocationVerification);
    }
  }
  return { nonce, presentations, presentationDefinitions, submissionData: presentationSubmission };
};

export const extractPresentationsFromAuthorizationResponse = async (
  response: AuthorizationResponse,
  opts?: { hasher?: Hasher }
): Promise<WrappedVerifiablePresentation[]> => {
  const wrappedVerifiablePresentations: WrappedVerifiablePresentation[] = [];
  if (response.payload.vp_token) {
    const presentations = Array.isArray(response.payload.vp_token) ? response.payload.vp_token : [response.payload.vp_token];
    for (const presentation of presentations) {
      wrappedVerifiablePresentations.push(CredentialMapper.toWrappedVerifiablePresentation(presentation, { hasher: opts?.hasher }));
    }
  }
  return wrappedVerifiablePresentations;
};

export const createPresentationSubmission = async (
  verifiablePresentations: W3CVerifiablePresentation[],
  opts?: { presentationDefinitions: (PresentationDefinitionWithLocation | IPresentationDefinition)[] }
): Promise<PresentationSubmission> => {
  let submission_data: PresentationSubmission;
  for (const verifiablePresentation of verifiablePresentations) {
    const wrappedPresentation = CredentialMapper.toWrappedVerifiablePresentation(verifiablePresentation);

    let submission: PresentationSubmission | undefined =
      CredentialMapper.isWrappedW3CVerifiablePresentation(wrappedPresentation) &&
      (wrappedPresentation.presentation.presentation_submission ??
        wrappedPresentation.decoded.presentation_submission ??
        (typeof wrappedPresentation.original !== 'string' && wrappedPresentation.original.presentation_submission));
    if (typeof submission === 'string') {
      submission = JSON.parse(submission);
    }
    if (!submission && opts?.presentationDefinitions) {
      console.log(`No submission_data in VPs and not provided. Will try to deduce, but it is better to create the submission data beforehand`);
      for (const definitionOpt of opts.presentationDefinitions) {
        const definition = 'definition' in definitionOpt ? definitionOpt.definition : definitionOpt;
        const result = new PEX().evaluatePresentation(definition, wrappedPresentation.original, { generatePresentationSubmission: true });
        if (result.areRequiredCredentialsPresent) {
          submission = result.value;
          break;
        }
      }
    }
    if (!submission) {
      throw Error('Verifiable Presentation has no submission_data, it has not been provided separately, and could also not be deduced');
    }
    // let's merge all submission data into one object
    if (!submission_data) {
      submission_data = submission;
    } else {
      // We are pushing multiple descriptors into one submission_data, as it seems this is something which is assumed in OpenID4VP, but not supported in Presentation Exchange (a single VP always has a single submission_data)
      Array.isArray(submission_data.descriptor_map)
        ? submission_data.descriptor_map.push(...submission.descriptor_map)
        : (submission_data.descriptor_map = [...submission.descriptor_map]);
    }
  }
  if (typeof submission_data === 'string') {
    submission_data = JSON.parse(submission_data);
  }
  return submission_data;
};

export const putPresentationSubmissionInLocation = async (
  authorizationRequest: AuthorizationRequest,
  responsePayload: AuthorizationResponsePayload,
  resOpts: AuthorizationResponseOpts,
  idTokenPayload?: IDTokenPayload
): Promise<void> => {
  const version = await authorizationRequest.getSupportedVersion();
  const idTokenType = await authorizationRequest.containsResponseType(ResponseType.ID_TOKEN);
  const authResponseType = await authorizationRequest.containsResponseType(ResponseType.VP_TOKEN);
  // const requestPayload = await authorizationRequest.mergedPayloads();
  if (!resOpts.presentationExchange) {
    return;
  } else if (resOpts.presentationExchange.verifiablePresentations.length === 0) {
    throw Error('Presentation Exchange options set, but no verifiable presentations provided');
  }
  if (
    !resOpts.presentationExchange.presentationSubmission &&
    (!resOpts.presentationExchange.verifiablePresentations || resOpts.presentationExchange.verifiablePresentations.length === 0)
  ) {
    throw Error(`Either a presentationSubmission or verifiable presentations are needed at this point`);
  }
  const submissionData =
    resOpts.presentationExchange.presentationSubmission ??
    (await createPresentationSubmission(resOpts.presentationExchange.verifiablePresentations, {
      presentationDefinitions: await authorizationRequest.getPresentationDefinitions(),
    }));

  const location =
    resOpts.presentationExchange?.vpTokenLocation ??
    (idTokenType && version < SupportedVersion.SIOPv2_D11 ? VPTokenLocation.ID_TOKEN : VPTokenLocation.AUTHORIZATION_RESPONSE);

  switch (location) {
    case VPTokenLocation.TOKEN_RESPONSE: {
      throw Error('Token response for VP token is not supported yet');
    }
    case VPTokenLocation.ID_TOKEN: {
      if (!idTokenPayload) {
        throw Error('Cannot place submission data _vp_token in id token if no id token is present');
      } else if (version >= SupportedVersion.SIOPv2_D11) {
        throw Error(`This version of the OpenID4VP spec does not allow to store the vp submission data in the ID token`);
      } else if (!idTokenType) {
        throw Error(`Cannot place vp token in ID token as the RP didn't provide an "openid" scope in the request`);
      }
      if (idTokenPayload._vp_token?.presentation_submission) {
        if (submissionData !== idTokenPayload._vp_token.presentation_submission) {
          throw Error('Different submission data was provided as an option, but exising submission data was already present in the id token');
        }
      } else {
        if (!idTokenPayload._vp_token) {
          idTokenPayload._vp_token = { presentation_submission: submissionData };
        } else {
          idTokenPayload._vp_token.presentation_submission = submissionData;
        }
      }
      break;
    }
    case VPTokenLocation.AUTHORIZATION_RESPONSE: {
      if (!authResponseType) {
        throw Error('Cannot place vp token in Authorization Response as there is no vp_token scope in the auth request');
      }
      if (responsePayload.presentation_submission) {
        if (submissionData !== responsePayload.presentation_submission) {
          throw Error(
            'Different submission data was provided as an option, but exising submission data was already present in the authorization response'
          );
        }
      } else {
        responsePayload.presentation_submission = submissionData;
      }
    }
  }

  responsePayload.vp_token =
    resOpts.presentationExchange?.verifiablePresentations.length === 1
      ? resOpts.presentationExchange.verifiablePresentations[0]
      : resOpts.presentationExchange?.verifiablePresentations;
};

export const assertValidVerifiablePresentations = async (args: {
  presentationDefinitions: PresentationDefinitionWithLocation[];
  presentations: WrappedVerifiablePresentation[];
  verificationCallback: PresentationVerificationCallback;
  opts?: {
    limitDisclosureSignatureSuites?: string[];
    restrictToFormats?: Format;
    restrictToDIDMethods?: string[];
    presentationSubmission?: PresentationSubmission;
    hasher?: Hasher;
  };
}) => {
  if (
    (!args.presentationDefinitions || args.presentationDefinitions.filter((a) => a.definition).length === 0) &&
    (!args.presentations || (Array.isArray(args.presentations) && args.presentations.filter((vp) => vp.presentation).length === 0))
  ) {
    return;
  }
  PresentationExchange.assertValidPresentationDefinitionWithLocations(args.presentationDefinitions);
  const presentationsWithFormat = args.presentations;

  if (args.presentationDefinitions && args.presentationDefinitions.length && (!presentationsWithFormat || presentationsWithFormat.length === 0)) {
    throw new Error(SIOPErrors.AUTH_REQUEST_EXPECTS_VP);
  } else if (
    (!args.presentationDefinitions || args.presentationDefinitions.length === 0) &&
    presentationsWithFormat &&
    presentationsWithFormat.length > 0
  ) {
    throw new Error(SIOPErrors.AUTH_REQUEST_DOESNT_EXPECT_VP);
  } else if (args.presentationDefinitions && presentationsWithFormat && args.presentationDefinitions.length != presentationsWithFormat.length) {
    throw new Error(SIOPErrors.AUTH_REQUEST_EXPECTS_VP);
  } else if (args.presentationDefinitions && !args.opts.presentationSubmission) {
    throw new Error(`No presentation submission present. Please use presentationSubmission opt argument!`);
  } else if (args.presentationDefinitions && presentationsWithFormat) {
    await PresentationExchange.validatePresentationsAgainstDefinitions(
      args.presentationDefinitions,
      presentationsWithFormat,
      args.verificationCallback,
      args.opts
    );
  }
};

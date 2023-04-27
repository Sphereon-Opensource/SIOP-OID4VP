import { CredentialMapper, PresentationSubmission, W3CVerifiablePresentation, WrappedVerifiablePresentation } from '@sphereon/ssi-types';

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
  const presentations = await extractPresentationsFromAuthorizationResponse(authorizationResponse);
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
  const submissionData = authorizationResponse.payload.presentation_submission
    ? authorizationResponse.payload.presentation_submission
    : idPayload?._vp_token?.presentation_submission;
  await assertValidVerifiablePresentations({
    presentationDefinitions,
    presentations,
    submissionData,
    verificationCallback: verifyOpts.verification.presentationVerificationCallback,
  });

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
  return { presentations, presentationDefinitions, submissionData };
};

export const extractPresentationsFromAuthorizationResponse = async (response: AuthorizationResponse): Promise<WrappedVerifiablePresentation[]> => {
  const wrappedVerifiablePresentations: WrappedVerifiablePresentation[] = [];
  if (response.payload.vp_token) {
    const presentations = Array.isArray(response.payload.vp_token) ? response.payload.vp_token : [response.payload.vp_token];
    for (const presentation of presentations) {
      wrappedVerifiablePresentations.push(CredentialMapper.toWrappedVerifiablePresentation(presentation));
    }
  }
  return wrappedVerifiablePresentations;
};

export const createSubmissionData = async (verifiablePresentations: W3CVerifiablePresentation[]): Promise<PresentationSubmission> => {
  let submission_data: PresentationSubmission;
  for (const verifiablePresentation of verifiablePresentations) {
    const wrappedPresentation = CredentialMapper.toWrappedVerifiablePresentation(verifiablePresentation);

    const submission =
      wrappedPresentation.presentation.presentation_submission ||
      wrappedPresentation.decoded.presentation_submission ||
      (typeof wrappedPresentation.original !== 'string' && wrappedPresentation.original.presentation_submission);
    if (!submission) {
      // todo in the future PEX might supply the submission_data separately as well
      throw Error('Verifiable Presentation has no submission_data');
    }
    if (!submission_data) {
      submission_data = submission;
    } else {
      // We are pushing multiple descriptors into one submission_data, as it seems this is something which is assumed in OpenID4VP, but not supported in Presentation Exchange (a single VP always has a single submission_data)
      Array.isArray(submission_data.descriptor_map)
        ? submission_data.descriptor_map.push(...submission.descriptor_map)
        : (submission_data.descriptor_map = [...submission.descriptor_map]);
    }
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
  const submissionData =
    resOpts.presentationExchange.submissionData ?? (await createSubmissionData(resOpts.presentationExchange.verifiablePresentations));

  const location = resOpts.presentationExchange?.vpTokenLocation ?? (idTokenType ? VPTokenLocation.ID_TOKEN : VPTokenLocation.AUTHORIZATION_RESPONSE);

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

  const vps =
    resOpts.presentationExchange?.verifiablePresentations?.map(
      (vp) => CredentialMapper.toWrappedVerifiablePresentation(vp).original as W3CVerifiablePresentation
    ) || [];
  responsePayload.vp_token = vps.length === 1 ? vps[0] : vps;
};

export const assertValidVerifiablePresentations = async (args: {
  presentationDefinitions: PresentationDefinitionWithLocation[];
  presentations: WrappedVerifiablePresentation[];
  submissionData?: PresentationSubmission;
  verificationCallback?: PresentationVerificationCallback;
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
  } else if (args.presentationDefinitions && presentationsWithFormat) {
    await PresentationExchange.validatePresentationsAgainstDefinitions(
      args.presentationDefinitions,
      presentationsWithFormat,
      args.submissionData,
      args.verificationCallback
    );
  }
};

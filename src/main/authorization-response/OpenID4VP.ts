import { IVerifiablePresentation, PresentationSubmission } from '@sphereon/ssi-types';

import { verifyRevocation } from '../helpers';
import { RevocationVerification, SIOPErrors, VerifiablePresentationPayload } from '../types';

import { AuthorizationResponse } from './AuthorizationResponse';
import { PresentationExchange } from './PresentationExchange';
import {
  AuthorizationResponseOpts,
  PresentationDefinitionWithLocation,
  PresentationLocation,
  PresentationVerificationCallback,
  VerifiablePresentationWithLocation,
  VerifyAuthorizationResponseOpts,
} from './types';

export const verifyPresentations = async (
  authorizationResponse: AuthorizationResponse,
  verifyOpts: VerifyAuthorizationResponseOpts
): Promise<void> => {
  const presentations = await extractPresentationsFromAuthorizationResponse(authorizationResponse);
  const presentationDefinitions = verifyOpts.presentationDefinitions
    ? Array.isArray(verifyOpts.presentationDefinitions)
      ? verifyOpts.presentationDefinitions
      : [verifyOpts.presentationDefinitions]
    : [];

  await assertValidVerifiablePresentations({
    presentationDefinitions,
    presentations,
    verificationCallback: verifyOpts.verification.presentationVerificationCallback,
  });

  const revocationVerification = verifyOpts.verification?.revocationOpts
    ? verifyOpts.verification.revocationOpts.revocationVerification
    : RevocationVerification.IF_PRESENT;
  if (revocationVerification !== RevocationVerification.NEVER) {
    for (const vp of presentations) {
      await verifyRevocation(vp, verifyOpts.verification.revocationOpts.revocationVerificationCallback, revocationVerification);
    }
  }
};

export const extractPresentationsFromAuthorizationResponse = async (
  response: AuthorizationResponse
): Promise<VerifiablePresentationWithLocation[]> => {
  const idToken = await response.idToken.payload();
  const presentationsWithLocation: VerifiablePresentationWithLocation[] = [];
  if (response.payload.vp_token) {
    const presentations = Array.isArray(response.payload.vp_token) ? response.payload.vp_token : [response.payload.vp_token];
    for (const presentation of presentations) {
      presentationsWithLocation.push({
        presentation: presentation as unknown as IVerifiablePresentation,
        location: PresentationLocation.VP_TOKEN,
        format: presentation.format,
      });
    }
  }
  if (idToken && idToken._vp_token) {
    const presentations = Array.isArray(idToken._vp_token) ? idToken._vp_token : [idToken._vp_token];
    for (const presentation of presentations) {
      presentationsWithLocation.push({
        presentation: presentation as unknown as IVerifiablePresentation,
        location: PresentationLocation.ID_TOKEN,
        format: presentation.format,
      });
    }
  }
  return presentationsWithLocation;
};

export const extractPresentations = (resOpts: AuthorizationResponseOpts) => {
  const presentationPayloads =
    resOpts.presentationExchange?.vps && resOpts.presentationExchange.vps.length > 0
      ? resOpts.presentationExchange.vps
          .filter((vp) => vp.location === PresentationLocation.ID_TOKEN)
          .map<VerifiablePresentationPayload>((vp) => vp as VerifiablePresentationPayload)
      : undefined;
  const vp_tokens =
    resOpts.presentationExchange?.vps && resOpts.presentationExchange.vps.length > 0
      ? resOpts.presentationExchange.vps
          .filter((vp) => vp.location === PresentationLocation.VP_TOKEN)
          .map<VerifiablePresentationPayload>((vp) => vp as VerifiablePresentationPayload)
      : undefined;
  let vp_token;
  if (vp_tokens) {
    if (vp_tokens.length == 1) {
      vp_token = vp_tokens[0];
    } else if (vp_tokens.length > 1) {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID);
    }
  }
  const verifiable_presentations = presentationPayloads && presentationPayloads.length > 0 ? presentationPayloads : undefined;
  return {
    verifiable_presentations,
    vp_token,
  };
};

export const assertValidVerifiablePresentations = async (args: {
  presentationDefinitions: PresentationDefinitionWithLocation[];
  presentations: VerifiablePresentationWithLocation[];
  verificationCallback?: PresentationVerificationCallback;
}) => {
  if (
    (!args.presentationDefinitions || args.presentationDefinitions.filter((a) => a.definition).length === 0) &&
    (!args.presentations || (Array.isArray(args.presentations) && args.presentations.filter((vp) => vp.presentation).length === 0))
  ) {
    return;
  }
  PresentationExchange.assertValidPresentationDefinitionWithLocations(args.presentationDefinitions);
  const presentationPayloads: VerifiablePresentationPayload[] = [];
  let presentationSubmission: PresentationSubmission;
  if (args.presentations && Array.isArray(args.presentations) && args.presentations.length > 0) {
    for (const presentationWithLocation of args.presentations) {
      presentationPayloads.push(presentationWithLocation.presentation as unknown as VerifiablePresentationPayload);
    }
    // TODO check how to handle multiple VPs
    if (args.presentations[0].presentation?.presentation_submission) {
      presentationSubmission = args.presentations[0].presentation.presentation_submission;
    }
  }

  if (args.presentationDefinitions && args.presentationDefinitions.length && (!presentationPayloads || presentationPayloads.length === 0)) {
    throw new Error(SIOPErrors.AUTH_REQUEST_EXPECTS_VP);
  } else if (
    (!args.presentationDefinitions || args.presentationDefinitions.length === 0) &&
    presentationPayloads &&
    presentationPayloads.length > 0
  ) {
    throw new Error(SIOPErrors.AUTH_REQUEST_DOESNT_EXPECT_VP);
  } else if (args.presentationDefinitions && presentationPayloads && args.presentationDefinitions.length != presentationPayloads.length) {
    throw new Error(SIOPErrors.AUTH_REQUEST_EXPECTS_VP);
  } else if (args.presentationDefinitions && presentationPayloads) {
    await PresentationExchange.validatePayloadsAgainstDefinitions(
      args.presentationDefinitions,
      presentationPayloads,
      presentationSubmission,
      args.verificationCallback
    );
  }
};

import { PresentationSubmission } from '@sphereon/ssi-types';

import { verifyRevocation } from '../functions';
import { AuthorizationResponsePayload, RevocationVerification, SIOPErrors, VerifiablePresentationPayload } from '../types';

import { PresentationExchange } from './PresentationExchange';
import {
  AuthorizationResponseOpts,
  PresentationDefinitionWithLocation,
  PresentationLocation,
  PresentationVerificationCallback,
  VerifyAuthorizationResponseOpts,
} from './types';

export const verifyPresentations = async (
  authorizationResponse: AuthorizationResponsePayload,
  verifyOpts: VerifyAuthorizationResponseOpts
): Promise<void> => {
  await assertValidVerifiablePresentations({
    presentationDefinitions: [
      {
        definition: verifyOpts.claims?.vpToken?.presentationDefinition,
        location: PresentationLocation.VP_TOKEN,
      },
    ],
    presentationPayloads: authorizationResponse.vp_token as VerifiablePresentationPayload[] | VerifiablePresentationPayload,
    verificationCallback: verifyOpts.verification.presentationVerificationCallback,
  });
  const revocationVerification = verifyOpts.verification?.revocationOpts
    ? verifyOpts.verification.revocationOpts.revocationVerification
    : RevocationVerification.IF_PRESENT;
  if (revocationVerification !== RevocationVerification.NEVER) {
    if (Array.isArray(authorizationResponse.vp_token)) {
      for (const vp of authorizationResponse.vp_token) {
        await verifyRevocation(vp, verifyOpts.verification.revocationOpts.revocationVerificationCallback, revocationVerification);
      }
    } else {
      await verifyRevocation(
        authorizationResponse.vp_token,
        verifyOpts.verification.revocationOpts.revocationVerificationCallback,
        revocationVerification
      );
    }
  }
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
  presentationPayloads: VerifiablePresentationPayload[] | VerifiablePresentationPayload;
  verificationCallback?: PresentationVerificationCallback;
}) => {
  if (
    (!args.presentationDefinitions || args.presentationDefinitions.filter((a) => a.definition).length === 0) &&
    (!args.presentationPayloads ||
      (Array.isArray(args.presentationPayloads) && args.presentationPayloads.filter((vp) => vp.presentation).length === 0))
  ) {
    return;
  }
  PresentationExchange.assertValidPresentationDefinitionWithLocations(args.presentationDefinitions);
  const presentationPayloads: VerifiablePresentationPayload[] = [];
  let presentationSubmission: PresentationSubmission;
  if (args.presentationPayloads && Array.isArray(args.presentationPayloads) && args.presentationPayloads.length > 0) {
    presentationPayloads.push(...args.presentationPayloads);
    // TODO check how to handle multiple VPs
    if (args.presentationPayloads[0].presentation?.presentation_submission) {
      presentationSubmission = args.presentationPayloads[0].presentation.presentation_submission;
    }
  } else if (args.presentationPayloads && !Array.isArray(args.presentationPayloads)) {
    presentationPayloads.push(args.presentationPayloads);
    if (args.presentationPayloads.presentation?.presentation_submission) {
      presentationSubmission = args.presentationPayloads.presentation.presentation_submission;
    }
  }

  if (args.presentationDefinitions && args.presentationDefinitions.length && (!presentationPayloads || presentationPayloads.length === 0)) {
    throw new Error(SIOPErrors.AUTH_REQUEST_EXPECTS_VP);
  } else if (
    (!args.presentationDefinitions || args.presentationDefinitions.length === 0) &&
    (presentationPayloads || presentationPayloads.length > 0)
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

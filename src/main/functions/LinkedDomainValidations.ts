import { IVerifyCredentialResult, WellKnownDidVerifier } from "@sphereon/wellknown-dids-client";

import { LinkedDomainValidationMode } from "../types/SIOP.types";

import { resolveDidDocument } from "./DIDResolution";

export async function validateWithDid(did: string, linkedDomainValidationMode: LinkedDomainValidationMode) {
  const verifyCallback = async (): Promise<IVerifyCredentialResult> => {
    return { verified: true };
  };
  const verifier = new WellKnownDidVerifier({
    verifySignatureCallback: () => verifyCallback(),
    onlyVerifyServiceDid: false,
  });

  const didDocument = await resolveDidDocument(did)
  await verifier.verifyDomainLinkage({didDocument: didDocument});
}
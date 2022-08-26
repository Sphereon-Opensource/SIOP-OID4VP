import { ProofType } from '@sphereon/pex';
import { Format } from '@sphereon/pex-models';

import { SigningAlgo, SIOPErrors, supportedCredentialsFormats } from '../../src/main';

describe('DidSiopMetadata should ', () => {
  it('find supportedCredentialsFormats correctly', async function () {
    const rpFormat: Format = {
      ldp_vc: {
        proof_type: [ProofType.EcdsaSecp256k1Signature2019, ProofType.EcdsaSecp256k1Signature2019],
      },
      jwt_vc: {
        alg: [SigningAlgo.ES256, SigningAlgo.ES256K],
      },
    };
    const opFormat: Format = {
      jwt_vc: {
        alg: [SigningAlgo.ES256, SigningAlgo.ES256K],
      },
    };
    expect(supportedCredentialsFormats(rpFormat, opFormat)).toStrictEqual({ jwt_vc: { alg: ['ES256', 'ES256K'] } });
  });

  it('throw CREDENTIAL_FORMATS_NOT_SUPPORTED for algs not matching', async function () {
    const rpFormat: Format = {
      ldp_vc: {
        proof_type: [ProofType.EcdsaSecp256k1Signature2019, ProofType.EcdsaSecp256k1Signature2019],
      },
      jwt_vc: {
        alg: [SigningAlgo.ES256K],
      },
    };
    const opFormat: Format = {
      jwt_vc: {
        alg: [SigningAlgo.ES256],
      },
    };
    expect(() => supportedCredentialsFormats(rpFormat, opFormat)).toThrow(SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED);
  });

  it('throw CREDENTIAL_FORMATS_NOT_SUPPORTED for types not matching', async function () {
    const rpFormat: Format = {
      ldp_vc: {
        proof_type: [ProofType.EcdsaSecp256k1Signature2019, ProofType.EcdsaSecp256k1Signature2019],
      },
    };
    const opFormat: Format = {
      jwt_vc: {
        alg: [SigningAlgo.ES256],
      },
    };
    expect(() => supportedCredentialsFormats(rpFormat, opFormat)).toThrow(SIOPErrors.CREDENTIAL_FORMATS_NOT_SUPPORTED);
  });

  it('throw CREDENTIALS_FORMATS_NOT_PROVIDED', async function () {
    const rpFormat: Format = {};
    const opFormat: Format = {
      jwt_vc: {
        alg: [SigningAlgo.ES256, SigningAlgo.ES256K],
      },
    };
    expect(() => supportedCredentialsFormats(rpFormat, opFormat)).toThrow(SIOPErrors.CREDENTIALS_FORMATS_NOT_PROVIDED);
  });
});

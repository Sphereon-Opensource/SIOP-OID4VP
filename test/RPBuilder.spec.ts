import { IVerifyCallbackArgs, IVerifyCredentialResult } from '@sphereon/wellknown-dids-client';

import { KeyAlgo, PassBy, ResponseType, RevocationVerification, RP, RPBuilder, Scope, SigningAlgo, SubjectType, SupportedVersion } from '../src/main';

const EXAMPLE_REDIRECT_URL = 'https://acme.com/hello';

const verifyCallback = async (_args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => ({ verified: true });

describe('rp builder should', () => {
   function getRPBuilder(): RPBuilder {
    const rpMockEntity = {
      hexPrivateKey: 'a1458fac9ea502099f40be363ad3144d6d509aa5aa3d17158a9e6c3b67eb0397',
      did: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98',
      didKey: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98#controller',
    };

    return RP.builder()
      .redirect(EXAMPLE_REDIRECT_URL)
      .addVerifyCallback(verifyCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .requestBy(PassBy.VALUE)
      .internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, rpMockEntity.didKey)
      .addDidMethod('ethr')
      .registrationBy({
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: { jwt_vc: { alg: [KeyAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subjectSyntaxTypesSupported: ['did', 'did:ethr'],
        registrationBy: { type: PassBy.VALUE },
      });
  }

  it('create the RP object successfully with supportedVersions', async () => {
    const rpBuilder = getRPBuilder();
    const rp: RP = rpBuilder.withSupportedVersions(['SIOPv2_ID1']).build();

    expect(rp.supportedVersions[0]).toStrictEqual('SIOPv2_ID1');
  });

  it('create the RP object successfully with supportedVersions objects', async () => {
    const rpBuilder = getRPBuilder();
    const rp: RP = rpBuilder.withSupportedVersions([SupportedVersion.SIOPv2_D11]).build();

    expect(rp.supportedVersions[0]).toStrictEqual('SIOPv2_D11');
  });

});

import { IVerifyCallbackArgs, IVerifyCredentialResult } from '@sphereon/wellknown-dids-client';

import { KeyAlgo, OP, OPBuilder, PassBy, ResponseIss, ResponseType, Scope, SigningAlgo, SubjectType, SupportedVersion } from '../src/main';

const verifyCallback = async (_args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => ({ verified: true });

describe('op builder should', () => {
   function getOPBuilder(): OPBuilder {
    const opMockEntity = {
      hexPrivateKey: 'a1458fac9ea502099f40be363ad3144d6d509aa5aa3d17158a9e6c3b67eb0397',
      did: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98',
      didKey: 'did:ethr:ropsten:0x028360fb95417724cb7dd2ff217b15d6f17fc45e0ffc1b3dce6c2b8dd1e704fa98#controller',
    };

    return OP.builder()
     .withExpiresIn(1000)
     .addVerifyCallback(verifyCallback)
     .addDidMethod('ethr')
     .internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, opMockEntity.didKey)
     .registrationBy({
       authorizationEndpoint: 'www.myauthorizationendpoint.com',
       idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
       issuer: ResponseIss.SELF_ISSUED_V2,
       requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
       responseTypesSupported: [ResponseType.ID_TOKEN],
       vpFormats: { jwt_vc: { alg: [KeyAlgo.EDDSA] } },
       scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
       subjectTypesSupported: [SubjectType.PAIRWISE],
       subjectSyntaxTypesSupported: [],
       registrationBy: { type: PassBy.VALUE },
     });
  }

  it('create the OP object successfully with supportedVersions', async () => {
    const opBuilder = getOPBuilder();
    const op: OP = opBuilder.withSupportedVersions(['SIOPv2_ID1']).build();

    expect(op.supportedVersions[0]).toStrictEqual('SIOPv2_ID1');
  });

  it('create the OP object successfully with supportedVersions objects', async () => {
    const opBuilder = getOPBuilder();
    const op: OP = opBuilder.withSupportedVersions([SupportedVersion.SIOPv2_D11]).build();

    expect(op.supportedVersions[0]).toStrictEqual('SIOPv2_D11');
  });

});

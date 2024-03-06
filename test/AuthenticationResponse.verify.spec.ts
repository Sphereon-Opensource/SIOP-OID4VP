import { IVerifyCallbackArgs, IVerifyCredentialResult } from '@sphereon/wellknown-dids-client';

import { IDToken, VerificationMode, VerifyAuthorizationResponseOpts } from '../src';
import SIOPErrors from '../src/types/Errors';

// const EXAMPLE_REDIRECT_URL = "https://acme.com/hello";
const DID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0';

const validButExpiredResJWT =
  'eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXRocjoweDk3NTgzNmREM0Y1RTk4QzE5RjBmM2I4N0Y5OWFGMzA1MDAyNkREQzIjY29udHJvbGxlciIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2MzIyNzE4MDMuMjEyLCJleHAiOjE2MzIyNzI0MDMuMjEyLCJpc3MiOiJodHRwczovL3NlbGYtaXNzdWVkLm1lL3YyIiwic3ViIjoiZGlkOmV0aHI6MHg5NzU4MzZkRDNGNUU5OEMxOUYwZjNiODdGOTlhRjMwNTAwMjZEREMyIiwiYXVkIjoiaHR0cHM6Ly9hY21lLmNvbS9oZWxsbyIsImRpZCI6ImRpZDpldGhyOjB4OTc1ODM2ZEQzRjVFOThDMTlGMGYzYjg3Rjk5YUYzMDUwMDI2RERDMiIsInN1Yl90eXBlIjoiZGlkIiwic3ViX2p3ayI6eyJraWQiOiJkaWQ6ZXRocjoweDk3NTgzNmREM0Y1RTk4QzE5RjBmM2I4N0Y5OWFGMzA1MDAyNkREQzIjY29udHJvbGxlciIsImt0eSI6IkVDIiwiY3J2Ijoic2VjcDI1NmsxIiwieCI6IkloUXVEek5BY1dvczVXeDd4U1NHMks2Zkp6MnBobU1nbUZ4UE1xaEU4XzgiLCJ5IjoiOTlreGpCMVgzaUtkRXZkbVFDbllqVm5PWEJyc2VwRGdlMFJrek1aUDN1TSJ9LCJzdGF0ZSI6ImQ2NzkzYjQ2YWIyMzdkMzczYWRkNzQwMCIsIm5vbmNlIjoiU1JXSzltSVpFd1F6S3dsZlZoMkE5SV9weUtBT0tnNDAtWDJqbk5aZEN0byIsInJlZ2lzdHJhdGlvbiI6eyJpc3N1ZXIiOiJodHRwczovL3NlbGYtaXNzdWVkLm1lL3YyIiwicmVzcG9uc2VfdHlwZXNfc3VwcG9ydGVkIjoiaWRfdG9rZW4iLCJhdXRob3JpemF0aW9uX2VuZHBvaW50Ijoib3BlbmlkOiIsInNjb3Blc19zdXBwb3J0ZWQiOiJvcGVuaWQiLCJpZF90b2tlbl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVTMjU2SyIsIkVkRFNBIl0sInJlcXVlc3Rfb2JqZWN0X3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTZLIiwiRWREU0EiXSwic3ViamVjdF90eXBlc19zdXBwb3J0ZWQiOiJwYWlyd2lzZSJ9fQ.coLQr2hQuMwEfYUd3HdFt-ixhsaicc37cC9cwmQ2U5hfxRhAb871s9G1GAo3qhsa9v3t0G1bTX2J9WhLaC5J_Q';

describe('verify JWT from Request JWT should', () => {
  const verifyOpts: VerifyAuthorizationResponseOpts = {
    correlationId: '1234',
    audience: DID,
    verification: {
      resolveOpts: {
        subjectSyntaxTypesSupported: ['did:ethr'],
      },
      mode: VerificationMode.INTERNAL,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      wellknownDIDVerifyCallback: async (_args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => ({ verified: true }),
    },
  };

  it('throw NO_JWT when no jwt is passed', async () => {
    expect.assertions(1);
    await expect(IDToken.verify(undefined as never, verifyOpts)).rejects.toThrow(SIOPErrors.NO_JWT);
  });
  it('throw VERIFY_BAD_PARAMS when no verifyOpts is passed', async () => {
    expect.assertions(1);
    await expect(IDToken.verify(validButExpiredResJWT, undefined as never)).rejects.toThrow(SIOPErrors.VERIFY_BAD_PARAMS);
  });

  it('throw JWT_ERROR when expired but valid JWT is passed in', async () => {
    expect.assertions(1);
    await expect(IDToken.verify(validButExpiredResJWT, { ...verifyOpts, audience: 'https://acme.com/hello' })).rejects.toThrow(
      /invalid_jwt: JWT has expired: exp: 1632272403/
    );
  });

  it('throw JWT_ERROR when expired but valid JWT is passed in', async () => {
    expect.assertions(1);
    await expect(IDToken.verify(validButExpiredResJWT, { ...verifyOpts, audience: 'https://acme.com/hello' })).rejects.toThrow(
      /invalid_jwt: JWT has expired: exp: 1632272403/
    );
  });
});

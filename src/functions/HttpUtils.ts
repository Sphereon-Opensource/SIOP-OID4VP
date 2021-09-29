import { fetch } from 'cross-fetch';

import { SIOPErrors } from '../types';
import { JWTPayload } from '../types/JWT.types';
import { AuthenticationResponseWithJWT } from '../types/SIOP.types';

export async function postWithBearerToken(url: string, body: JWTPayload, bearerToken: string): Promise<Response> {
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${bearerToken}`,
      },
      body: JSON.stringify(body),
    });
    if (!response || !response.status || (response.status !== 200 && response.status !== 201)) {
      throw new Error(
        `${SIOPErrors.RESPONSE_STATUS_UNEXPECTED} ${response.status}:${response.statusText}, ${await response.text()}`
      );
    }
    return response;
  } catch (error) {
    throw new Error(`${(error as Error).message}`);
  }
}

export async function postAuthenticationResponse(url: string, body: AuthenticationResponseWithJWT): Promise<Response> {
  return postAuthenticationResponseJwt(url, body.jwt);
}

export async function postAuthenticationResponseJwt(url: string, jwt: string): Promise<Response> {
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
      },
      body: `id_token=${jwt}`,
    });
    if (!response || !response.status || response.status < 200 || response.status >= 400) {
      throw new Error(
        `${SIOPErrors.RESPONSE_STATUS_UNEXPECTED} ${response.status}:${response.statusText}, ${await response.text()}`
      );
    }
    return response;
  } catch (error) {
    throw new Error(`${(error as Error).message}`);
  }
}

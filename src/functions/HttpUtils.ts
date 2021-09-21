import { fetch } from 'cross-fetch';

import { SIOPErrors } from '../types';
import { JWTPayload } from '../types/JWT.types';

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

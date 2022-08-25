import nock from 'nock';

import { postWithBearerToken } from '../src/main';
import { SIOPErrors } from '../src/main/types';

const URL = 'https://example.com';
nock(URL)
  .post('/404', { iss: 'mock' }, { reqheaders: { Authorization: 'Bearer bearerToken' } })
  .reply(404, 'Not found');
nock(URL)
  .post('/200', { iss: 'mock' }, { reqheaders: { Authorization: 'Bearer bearerToken' } })
  .reply(200, '{"status": "ok"}');
nock(URL)
  .post('/201', { iss: 'mock' }, { reqheaders: { Authorization: 'Bearer bearerToken' } })
  .reply(201, '{"status": "ok"}');

describe('HttpUtils should', () => {
  it('throw Error when response is not 200 or 201', async () => {
    expect.assertions(1);
    await expect(postWithBearerToken(`${URL}/404`, { iss: 'mock' }, 'bearerToken')).rejects.toThrowError(SIOPErrors.RESPONSE_STATUS_UNEXPECTED);
  });

  it('return response when response HTTP status is 200', async () => {
    expect.assertions(1);
    await expect(postWithBearerToken(`${URL}/200`, { iss: 'mock' }, 'bearerToken').then((value) => value.json())).resolves.toMatchObject({
      status: 'ok',
    });
  });
  it('return response when response HTTP status is 201', async () => {
    expect.assertions(1);
    await expect(postWithBearerToken(`${URL}/201`, { iss: 'mock' }, 'bearerToken').then((value) => value.json())).resolves.toMatchObject({
      status: 'ok',
    });
  });
});

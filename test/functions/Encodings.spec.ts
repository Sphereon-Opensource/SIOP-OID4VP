import { encodeAsUriValue, encodeJsonAsURI } from '../../src';

describe('Encodings', () => {
  test('encodeAsUriValue', () => {
    expect(encodeAsUriValue(undefined, { a: { b: { c: 'd', e: 'f' } } })).toBe('a[b][c]=d&a[b][e]=f');

    expect(encodeAsUriValue(undefined, { a: ['b', 'c', 'd'] })).toBe('a[0]=b&a[1]=c&a[2]=d');

    expect(
      encodeAsUriValue(undefined, {
        a: {
          b: {
            'a$s939very-2eweird-==key': {
              c: 'd',
            },
          },
        },
      })
    ).toBe('a[b][a%24s939very-2eweird-%3D%3Dkey][c]=d');
  });

  test('encodeJsonAsURI', () => {
    const encoded = encodeJsonAsURI(
      {
        presentation_submission: {
          id: 'bbYJTQe7YPvVx-3rLl4Aq',
          definition_id: '000fc41b-2859-4fc3-b797-510492a9479a',
          descriptor_map: [
            {
              id: 'OpenBadgeCredential',
              format: 'jwt_vp',
              path: '$',
              path_nested: {
                id: 'OpenBadgeCredential',
                format: 'jwt_vc_json',
                path: '$.vp.verifiableCredential[0]',
              },
            },
          ],
        },
      },
      ['presentation_submission']
    );

    expect(encoded).toBe(
      `presentation_submission=id%3DbbYJTQe7YPvVx-3rLl4Aq%26definition_id%3D000fc41b-2859-4fc3-b797-510492a9479a%26descriptor_map%255B0%255D%255Bid%255D%3DOpenBadgeCredential%26descriptor_map%255B0%255D%255Bformat%255D%3Djwt_vp%26descriptor_map%255B0%255D%255Bpath%255D%3D%2524%26descriptor_map%255B0%255D%255Bpath_nested%255D%255Bid%255D%3DOpenBadgeCredential%26descriptor_map%255B0%255D%255Bpath_nested%255D%255Bformat%255D%3Djwt_vc_json%26descriptor_map%255B0%255D%255Bpath_nested%255D%255Bpath%255D%3D%2524.vp.verifiableCredential%255B0%255D`
    );
  });
});

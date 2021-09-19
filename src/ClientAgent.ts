import { Resolvable } from 'did-resolver';

import { DIDJwt, Keys } from './functions';
import { AkeResponse } from './types/AuthKeyExchange-types';

export default class ClientAgent {
  private readonly privateKey: string;
  private readonly did: string;
  private resolver: Resolvable;
  private readonly audience: string;

  /**
   * Creates the client application agent (the OP)
   *
   * @param   {String}        opts.privateKey    The private key associated with a DIDres
   * @param   {Resolvable}    opts.resolver      The DIDres resolver to use
   * @param   {}              opts                Optional options
   */
  constructor(opts?: { resolver: Resolvable; privateKey: string; did: string; audience?: string }) {
    this.did = opts?.did;
    this.audience = opts?.audience;
    this.setResolver(opts.resolver);
    this.privateKey = opts.privateKey;
  }

  /**
   * Sets the resolver to use for Relying Party Auth
   * @param resolver
   */
  setResolver(resolver: Resolvable) {
    this.resolver = resolver;
  }

  getDID() {
    return this.did;
  }

  /**
   * Verifies the Authenticated Key Exchange Response which contains the Access Token, Returns the decrypted access token
   *
   * @param {AkeResponse}     response  The AKE response, containing the encrypted access token
   * @param {String}          nonce     The nonce used
   */
  async verifyAuthResponse(response: AkeResponse, nonce: string): Promise<string> {
    const decryptedPayload = JSON.parse(
      await Keys.decrypt(this.privateKey, response.signed_payload.encrypted_access_token)
    );

    if (typeof decryptedPayload.did !== 'string' || typeof decryptedPayload.access_token !== 'string') {
      throw new Error('did or access_token invalid type');
    } else if (nonce !== decryptedPayload.nonce) {
      throw new Error(`Expected nonce ${nonce}. Received ${decryptedPayload.nonce}`);
    }

    const jwt = await DIDJwt.verifyDidJWT(decryptedPayload.access_token, this.resolver, { audience: this.audience });
    console.log(jwt);
    return decryptedPayload.access_token;
  }
}

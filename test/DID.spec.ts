import { UniResolver } from '@sphereon/did-uni-client';
import base58 from 'bs58';
import { EthrDID } from 'ethr-did';

describe('Ethr DID should', () => {
  jest.setTimeout(10000);
  it('succeed creating a DID on ethereum testnet', async () => {
    const network = 'ropsten';

    const keypair = EthrDID.createKeyPair();
    const ethrDid = new EthrDID({ ...keypair, chainNameOrId: network });

    /*  console.log(
      `private key (hex): ${keypair.privateKey.replace('0x', '')}\n` +
        `public key (hex): ${keypair.publicKey.replace('0x', '')}\n` +
        `DID: ${ethrDid.did}`
    );
*/
    const uniResolver = new UniResolver();
    await expect(uniResolver.resolve(ethrDid.did)).resolves.toMatchObject({
      didDocument: {},
    });

    const privateKeyBase58 = base58.encode(Buffer.from(keypair.privateKey.replace('0x', ''), 'hex'));
    const publicKeyBase58 = base58.encode(Buffer.from(keypair.publicKey.replace('0x', ''), 'hex'));
    console.log(`private key (base58): ${privateKeyBase58}\n` + `public key (base58): ${publicKeyBase58}`);
  });
});

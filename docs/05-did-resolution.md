
## DID resolution


### Description

Resolves the DID to a DID document using the DID method provided in didUrl and using DIFs [did-resolver](https://github.com/decentralized-identity/did-resolver) and Sphereon's [Universal registrar and resolver client](https://github.com/Sphereon-Opensource/did-uni-client).

This process allows retrieving public keys and verificationMethod material, as well as services provided by a DID controller. Can be used in both the webapp and mobile applications. Uses the did-uni-client, but could use other DIF did-resolver drivers as well. The benefit of the uni client is that it can resolve many DID methods. Since the resolution itself is provided by the mentioned external dependencies above, we suffice with a usage example.

#### Usage

```typescript
import {Resolver} from 'did-resolver'
import {getResolver as getUniResolver} from '@sphereon/did-uni-client'

const resolver = new Resolver(getUniResolver({
  subjectSyntaxTypesSupported: ['did:ethr:']
}));

resolver.resolve('did:ethr:0x998D43DA5d9d78500898346baf2d9B1E39Eb0Dda').then(doc => console.log)
```

The DidResolution file exposes 2 functions that help with the resolution as well:

```typescript
import {getResolver, resolveDidDocument} from './functions/DIDResolution';

// combines 2 uni resolvers for ethr and eosio together with the myCustomResolver and return that as a single resolver
const myCustomResolver = new MyCustomResolver();
getResolver({
  subjectSyntaxTypesSupported: ['did:ethr:', 'did:eosio:'], resolver: myCustomResolver});

// Returns a DID document for the specified DID, using the universal resolver client for the ehtr DID method
await resolveDidDocument('did:ethr:0x998D43DA5d9d78500898346baf2d9B1E39Eb0Dda', {subjectSyntaxTypesSupported: ['did:ethr:', 'did:eosio:']});
```

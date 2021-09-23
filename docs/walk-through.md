# Walk-through

This document is a walk-through for using the SIOP authentication library. This works at the low level, so without any HTTP endpoints involved.

---
**NOTE**

This document uses eosio DIDs, but these could be other DIDs as well. The creation of DIDs is out of scope and we are using a manual process here. We provide a [manual eosio DID walk-through](eosio-dids-testnet.md) if you want to test it yourself without having DIDs currently.

---


## Relying Party and SIOP should have keys and DIDs
Since the library uses DIDs for both the Relying Party and the Self-Issued OpenID Provider, we expect these DIDs to be present on both sides, as well as the respective parties having access to their private key(s). How DIDs are created is out of scope of this library, but we provide a [manual eosio DID walk-through](eosio-dids-testnet.md) if you want to test it yourself without having DIDs.



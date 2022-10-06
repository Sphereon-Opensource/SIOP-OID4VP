<h1 style="text-align: center; vertical-align: middle">
  <div style="text-align: center;">
    <a href="https://www.gimly.io/"><img src="https://avatars.githubusercontent.com/u/64525639?s=200&v=4" alt="Gimly" width="120" style="vertical-align: middle">
    </a> &nbsp;and &nbsp; 
    <a href="https://www.sphereon.com">
        <img src="https://sphereon.com/content/themes/sphereon/assets/img/logo.svg" alt="Sphereon" width="320" style="vertical-align: middle" >
    </a>
  </div> Self Issued OpenID Provider v2 (SIOP)
</h1>

<br/>

[![CI](https://github.com/Sphereon-Opensource/did-auth-siop/actions/workflows/main.yml/badge.svg)](https://github.com/Sphereon-Opensource/did-auth-siop/actions/workflows/main.yml) [![codecov](https://codecov.io/gh/Sphereon-Opensource/did-auth-siop/branch/develop/graph/badge.svg?token=9P1JGUYA35)](https://codecov.io/gh/Sphereon-Opensource/did-auth-siop) [![NPM Version](https://img.shields.io/npm/v/@sphereon/did-auth-siop.svg)](https://npm.im/@sphereon/did-auth-siop)

An authentication library so that clients/people conform to
the [Self Issued OpenID Provider v2 (SIOPv2)](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)
and  [OpenID Connect for Verifiable Presentations (OIDC4VP)](https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html)
as specified in the OpenID Connect working group.


## Introduction


SIOP v2 is an extension of OpenID Connect to allow end-users to act as OpenID Providers (OPs) themselves. Using
Self-Issued OPs, end-users can authenticate themselves and present claims directly to the Relying Parties (RPs),
typically a webapp, without relying on a third-party Identity Provider. This makes the solution fully self sovereign, as
it does not rely on any third parties and strictly happens peer 2 peer, but still uses the OpenID Connect protocol.

Next to the user acting as an OpenID Provider, this library also includes support for Verifiable Presentations using
the [Presentation Exchange](https://identity.foundation/presentation-exchange/) support provided by
our [PEX](https://github.com/Sphereon-Opensource/pex) library. This means that the Relying Party can pose submission
requirements on the Verifiable Credentials it would like to receive from the client/OP. The OP then checks whether it
has the credentials to support the submission requirements. Only if that is the case it will send the relevant (parts of
the) credentials as a Verifiable Presentation in the Authentication Response destined for the Webapp/Relying Party. Relying party in turn checks validity of the Verifiable Presentation(s) as well as the match with the submission
requirements. Only if everything is verified successfully the RP serves the protected page(s). This means that the
authentication can be extended with claims about the authenticating entity, but it can also be used to easily consume
credentials from supporting applications, without having to setup DIDComm connections for instance.

The term Self-Issued comes from the fact that the end-users (OP) issue self-signed ID Tokens to prove validity of the
identifiers and claims. This is a trust model different from that of the rest of OpenID Connect where OP is run by the
third party who issues ID Tokens on behalf of the end-user to the Relying Party upon the end-user's consent. This means
the end-user is in control about his/her data instead of the 3rd party OP.

Demo: https://vimeo.com/630104529 and a more stripped down demo: https://youtu.be/cqoKuQWPj-s


## Active Development


_IMPORTANT: This software still is in **VERY** early development stage. As such you should expect breaking changes in APIs, we
expect to keep that to a minimum though._


## Functionality


The DID Auth SIOP v2 library consists of a group of services and classes to:

- [Decentralized Identifiers (DID)](https://www.w3.org/TR/did-core/) method neutral: Resolve DIDs using
  DIFs [did-resolver](https://github.com/decentralized-identity/did-resolver) and
  Sphereon's [Universal registrar and resolver client](https://github.com/Sphereon-Opensource/did-uni-client)
- Verify and Create Json Web Tokens (JWTs) as used in OpenID Connect using Decentralized Identifiers (DIDs)
- OP class to create Authentication Requests and verify Authentication Responses
- RP class to verify Authentication Requests and create Authentication Responses
- Verifiable Presentation and Presentation Exchange support on the RP and OP sides

### [Steps involved](./docs/01-steps-involved.md)

### [OP and RP setup and interactions](./docs/02.0-op-and-rp-setup-and-interactions.md)

### [AuthenticationRequest class](./docs/03-auth-request-class.md)

### [Authentication Response Class](./docs/04-authentication-response-class.md)

### [DID resolution](./docs/05-did-resolution.md)

### [JWT and DID creation and Verification](./docs/06-jwt-and-did-creation-and-verification.md)

### [Class and Flow diagram of the interactions](./docs/07-class-and-flow-diagram-of-interaction.md)

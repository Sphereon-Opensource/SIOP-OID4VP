
## Steps involved


### Flow diagram:

![Flow diagram](https://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/Sphereon-Opensource/did-auth-siop/develop/docs/auth-flow.puml)

### Explanation:

1. Client (OP) initiates an auth-request by POST-ing to an endpoint, like for instance `/did-siop/v1/authentications` or clicking a Login button and scanning a QR code
2. Web (RP) receives the request and access the RP object which creates the authentication request as JWT, signs it and returns the response as an OpenID Connect URI
   1. JWT example:
     ```json
       // JWT Header
       {
         "alg": "ES256K",
         "kid": "did:ethr:0xcBe71d18b5F1259faA9fEE8f9a5FAbe2372BE8c9#controller",
         "typ": "JWT"
       }
   
       // JWT Payload
       {
         "iat": 1632336634,
         "exp": 1632337234,
         "response_type": "id_token",
         "scope": "openid",
         "client_id": "did:ethr:0xcBe71d18b5F1259faA9fEE8f9a5FAbe2372BE8c9",
         "redirect_uri": "https://acme.com/siop/v1/sessions",
         "iss": "did:ethr:0xcBe71d18b5F1259faA9fEE8f9a5FAbe2372BE8c9",
         "response_mode": "post",
         "claims": ...,
         "nonce": "qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg",
         "state": "b32f0087fc9816eb813fd11f",
         "registration": {
           "did_methods_supported": [
             "did:ethr:",
             "did:eosio:"
           ],
           "subject_identifiers_supported": "did"
         }
       }
     ```

   2. The Signed JWT, called the JWS follows the following scheme (JWS Compact Serialization, https://datatracker.ietf.org/doc/html/rfc7515#section-7.1): `BASE64URL(UTF8(JWT Protected Header)) || '.' || BASE64URL(JWT Payload) || '.' || BASE64URL(JWS Signature)`

   3. Create the URI containing the JWS:

      ```
      openid://?response_type=id_token 
        &scope=openid
        &client_id=did%3Aethr%3A0xBC9484414c1DcA4Aa85BadBBd8a36E3973934444
        &redirect_uri=https%3A%2F%2Frp.acme.com%2Fsiop%2Fjwts
        &iss=did%3Aethr%3A0xBC9484414c1DcA4Aa85BadBBd8a36E3973934444
        &response_mode=post
        &claims=...
        &state=af0ifjsldkj
        &nonce=qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg&state=b32f0087fc9816eb813fd11f
        &registration=%5Bobject%20Object%5D
        &request=<JWS here>
      ```

   4. `claims` param can be either a `vp_token` or an `id_token`:

        ```json
        // vp_token example
        {
            "id_token": {
                "email": null
            },
            "vp_token": {
                "presentation_definition": {
                    "input_descriptors": [
                        {
                            "schema": [
                                {
                                    "uri": "https://www.w3.org/2018/credentials/examples/v1/IDCardCredential"
                                }
                            ],
                            "constraints": {
                                "limit_disclosure": "required",
                                "fields": [
                                    {
                                        "path": [
                                            "$.vc.credentialSubject.given_name"
                                        ]
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
        }
    
        // id_token example
        {
            "userinfo": {
                "verifiable_presentations": [
                    "presentation_definition": {
                        "input_descriptors": [
                            {
                                "schema": [
                                    {
                                        "uri": "https://did.itsourweb.org:3000/smartcredential/Ontario-Health-Insurance-Plan"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
            "id_token": {
                "auth_time": {
                    "essential": true
                }
            }
        }
        ```

3. Web receives the Auth Request URI Object from RP

4. Web sends the Auth Request URI in the response body to the client

5. Client accesses OP object to create an Authentication response

6. OP verifies the authentication request, including checks on whether the RP DID and key-types are supported, next to whether the OP can satisfy the RPs requested Verifiable Credentials or not.

7. Presentation Exchange process in case the RP requested presentation definitions in the claims (see Presentation Exchange chapter)

8. OP creates the authentication response object as follows:

    1. Create an ID token as shown below:

    ```json
    // JWT encoded ID Token
    // JWT Header
    {
      "alg": "ES256K",
      "kid": "did:ethr:0x998D43DA5d9d78500898346baf2d9B1E39Eb0Dda#keys-1",
      "typ": "JWT"
    }
    
    // JWT Payload
    {
      "iat": 1632343857.084,
      "exp": 1632344857.084,
      "iss": "https://self-issued.me/v2",
      "sub": "did:ethr:0x998D43DA5d9d78500898346baf2d9B1E39Eb0Dda",
      "aud": "https://acme.com/siop/v1/sessions",
      "did": "did:ethr:0x998D43DA5d9d78500898346baf2d9B1E39Eb0Dda",
      "sub_type": "did",
      "sub_jwk": {
        "kid": "did:ethr:0x998D43DA5d9d78500898346baf2d9B1E39Eb0Dda#key-1",
        "kty": "EC",
        "crv": "secp256k1",
        "x": "a4IvJILPHe3ddGPi9qvAyXY9qMTEHvQw5DpQYOJVA0c",
        "y": "IKOy0JfBF8FOlsOJaC41xiKuGc2-_iqTI01jWHYIyJU"
      },
        "nonce": "qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg",
        "state": "b32f0087fc9816eb813fd11f",
        "registration": {
          "issuer": "https://self-issued.me/v2",
          "response_types_supported": "id_token",
          "authorization_endpoint": "openid:",
          "scopes_supported": "openid",
          "id_token_signing_alg_values_supported": [
            "ES256K",
            "EdDSA"
          ],
          "request_object_signing_alg_values_supported": [
            "ES256K",
            "EdDSA"
          ],
          "subject_types_supported": "pairwise"
        }
    }
    ```

    2. Sign the ID token using the DID key (kid) using JWS scheme (JWS Compact Serialization, https://datatracker.ietf.org/doc/html/rfc7515#section-7.1) and send it to the RP: `BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)`

9. OP returns the Auth response and jwt object to the client

10. Client does an HTTP POST to redirect_uri from the request (and the aud in the
response): https://acme.com/siop/v1/sessions using "application/x-www-form-urlencoded"

11. Web receives the ID token (auth response) and uses the RP's object verify method

12. RP performs the validation of the token, including signature validation, expiration and Verifiable Presentations if any. It returns the Verified Auth Response to WEB

13. WEB returns a 200 response to Client with a redirect to another page (logged in or confirmation of VP receipt etc.). From that moment on Client can use the Auth Response as bearer token as long as it is valid

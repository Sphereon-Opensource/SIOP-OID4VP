export const AuthenticationResponseOptsSchema = {
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$ref": "#/definitions/AuthenticationResponseOpts",
  "definitions": {
    "AuthenticationResponseOpts": {
      "type": "object",
      "properties": {
        "redirectUri": {
          "type": "string"
        },
        "signatureType": {
          "anyOf": [
            {
              "$ref": "#/definitions/InternalSignature"
            },
            {
              "$ref": "#/definitions/ExternalSignature"
            },
            {
              "$ref": "#/definitions/SuppliedSignature"
            }
          ]
        },
        "nonce": {
          "type": "string"
        },
        "state": {
          "type": "string"
        },
        "registration": {
          "$ref": "#/definitions/ResponseRegistrationOpts"
        },
        "responseMode": {
          "$ref": "#/definitions/ResponseMode"
        },
        "did": {
          "type": "string"
        },
        "vp": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/VerifiablePresentationResponseOpts"
          }
        },
        "expiresIn": {
          "type": "number"
        }
      },
      "required": [
        "signatureType",
        "registration",
        "did"
      ],
      "additionalProperties": false
    },
    "InternalSignature": {
      "type": "object",
      "properties": {
        "hexPrivateKey": {
          "type": "string"
        },
        "did": {
          "type": "string"
        },
        "kid": {
          "type": "string"
        }
      },
      "required": [
        "hexPrivateKey",
        "did"
      ],
      "additionalProperties": false
    },
    "ExternalSignature": {
      "type": "object",
      "properties": {
        "signatureUri": {
          "type": "string"
        },
        "did": {
          "type": "string"
        },
        "authZToken": {
          "type": "string"
        },
        "hexPublicKey": {
          "type": "string"
        },
        "kid": {
          "type": "string"
        }
      },
      "required": [
        "signatureUri",
        "did"
      ],
      "additionalProperties": false
    },
    "SuppliedSignature": {
      "type": "object",
      "properties": {
        "did": {
          "type": "string"
        },
        "kid": {
          "type": "string"
        }
      },
      "required": [
        "did",
        "kid"
      ],
      "additionalProperties": true
    },
    "ResponseRegistrationOpts": {
      "type": "object",
      "properties": {
        "authorizationEndpoint": {
          "type": "string"
        },
        "scopesSupported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/Scope"
              }
            },
            {
              "$ref": "#/definitions/Scope"
            }
          ]
        },
        "subjectTypesSupported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/SubjectType"
              }
            },
            {
              "$ref": "#/definitions/SubjectType"
            }
          ]
        },
        "idTokenSigningAlgValuesSupported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/KeyAlgo"
              }
            },
            {
              "$ref": "#/definitions/KeyAlgo"
            }
          ]
        },
        "requestObjectSigningAlgValuesSupported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/SigningAlgo"
              }
            },
            {
              "$ref": "#/definitions/SigningAlgo"
            }
          ]
        },
        "didsSupported": {
          "type": "boolean"
        },
        "didMethodsSupported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "type": "string"
              }
            },
            {
              "type": "string"
            }
          ]
        },
        "credentialSupported": {
          "type": "boolean"
        },
        "credentialEndpoint": {
          "type": "string"
        },
        "credentialFormatsSupported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/CredentialFormat"
              }
            },
            {
              "$ref": "#/definitions/CredentialFormat"
            }
          ]
        },
        "credentialClaimsSupported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "type": "string"
              }
            },
            {
              "type": "string"
            }
          ]
        },
        "credentialName": {
          "type": "string"
        },
        "registrationBy": {
          "$ref": "#/definitions/RegistrationType"
        }
      },
      "required": [
        "registrationBy"
      ],
      "additionalProperties": false
    },
    "Scope": {
      "type": "string",
      "enum": [
        "openid",
        "openid did_authn"
      ]
    },
    "SubjectType": {
      "type": "string",
      "enum": [
        "public",
        "pairwise"
      ]
    },
    "KeyAlgo": {
      "type": "string",
      "enum": [
        "EdDSA",
        "RS256",
        "ES256",
        "ES256K"
      ]
    },
    "SigningAlgo": {
      "type": "string",
      "enum": [
        "EdDSA",
        "RS256",
        "ES256",
        "ES256K",
        "none"
      ]
    },
    "CredentialFormat": {
      "type": "string",
      "enum": [
        "w3cvc-jsonld",
        "jwt"
      ]
    },
    "RegistrationType": {
      "type": "object",
      "properties": {
        "type": {
          "type": "string",
          "enum": [
            "REFERENCE",
            "VALUE"
          ]
        },
        "referenceUri": {
          "type": "string"
        },
        "id_token_encrypted_response_alg": {
          "$ref": "#/definitions/EncKeyAlgorithm"
        },
        "id_token_encrypted_response_enc": {
          "$ref": "#/definitions/EncSymmetricAlgorithmCode"
        }
      },
      "additionalProperties": false,
      "required": [
        "type"
      ]
    },
    "EncKeyAlgorithm": {
      "type": "string",
      "const": "ECDH-ES"
    },
    "EncSymmetricAlgorithmCode": {
      "type": "string",
      "const": "XC20P"
    },
    "ResponseMode": {
      "type": "string",
      "enum": [
        "fragment",
        "form_post",
        "post",
        "query"
      ]
    },
    "VerifiablePresentationResponseOpts": {
      "type": "object",
      "properties": {
        "format": {
          "$ref": "#/definitions/VerifiablePresentationTypeFormat"
        },
        "presentation": {
          "$ref": "#/definitions/IPresentation"
        },
        "location": {
          "$ref": "#/definitions/PresentationLocation"
        }
      },
      "required": [
        "format",
        "location",
        "presentation"
      ],
      "additionalProperties": false
    },
    "VerifiablePresentationTypeFormat": {
      "type": "string",
      "enum": [
        "jwt_vp",
        "ldp_vp"
      ]
    },
    "IPresentation": {
      "type": "object",
      "properties": {
        "@context": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "type": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "verifiableCredential": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/IVerifiableCredential"
          }
        },
        "presentation_submission": {
          "$ref": "#/definitions/PresentationSubmission"
        },
        "holder": {
          "type": "string"
        }
      },
      "required": [
        "@context",
        "type",
        "verifiableCredential"
      ],
      "additionalProperties": false
    },
    "IVerifiableCredential": {
      "anyOf": [
        {
          "$ref": "#/definitions/IJwtVerifiableCredential"
        },
        {
          "$ref": "#/definitions/IJsonLdVerifiableCredential"
        }
      ]
    },
    "IJwtVerifiableCredential": {
      "type": "object",
      "properties": {
        "proof": {
          "anyOf": [
            {
              "$ref": "#/definitions/IProof"
            },
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/IProof"
              }
            }
          ]
        },
        "aud": {
          "type": "string"
        },
        "exp": {
          "type": [
            "string",
            "number"
          ]
        },
        "iss": {
          "type": "string"
        },
        "jti": {
          "type": "string"
        },
        "nbf": {
          "type": [
            "string",
            "number"
          ]
        },
        "sub": {
          "type": "string"
        },
        "vc": {
          "$ref": "#/definitions/BaseCredential"
        }
      },
      "required": [
        "iss",
        "proof",
        "vc"
      ]
    },
    "IProof": {
      "type": "object",
      "properties": {
        "type": {
          "anyOf": [
            {
              "$ref": "#/definitions/ProofType"
            },
            {
              "type": "string"
            }
          ]
        },
        "created": {
          "type": "string"
        },
        "proofPurpose": {
          "anyOf": [
            {
              "$ref": "#/definitions/ProofPurpose"
            },
            {
              "type": "string"
            }
          ]
        },
        "verificationMethod": {
          "type": "string"
        },
        "challenge": {
          "type": "string"
        },
        "domain": {
          "type": "string"
        },
        "proofValue": {
          "type": "string"
        },
        "jws": {
          "type": "string"
        },
        "nonce": {
          "type": "string"
        },
        "requiredRevealStatements": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "required": [
        "type",
        "created",
        "proofPurpose",
        "verificationMethod"
      ],
      "additionalProperties": {
        "anyOf": [
          {
            "type": "string"
          },
          {
            "type": "array",
            "items": {
              "type": "string"
            }
          },
          {
            "not": {}
          }
        ]
      }
    },
    "ProofType": {
      "type": "string",
      "enum": [
        "Ed25519Signature2018",
        "Ed25519Signature2020",
        "EcdsaSecp256k1Signature2019",
        "EcdsaSecp256k1RecoverySignature2020",
        "JsonWebSignature2020",
        "RsaSignature2018",
        "GpgSignature2020",
        "JcsEd25519Signature2020",
        "BbsBlsSignatureProof2020",
        "BbsBlsBoundSignatureProof2020"
      ]
    },
    "ProofPurpose": {
      "type": "string",
      "enum": [
        "assertionMethod",
        "authentication",
        "keyAgreement",
        "contactAgreement",
        "capabilityInvocation",
        "capabilityDelegation"
      ]
    },
    "BaseCredential": {
      "type": "object",
      "properties": {
        "@context": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "type": "string"
              }
            },
            {
              "type": "string"
            }
          ]
        },
        "credentialStatus": {
          "$ref": "#/definitions/ICredentialStatus"
        },
        "credentialSubject": {
          "$ref": "#/definitions/ICredentialSubject"
        },
        "credentialSchema": {
          "anyOf": [
            {
              "$ref": "#/definitions/ICredentialSchema"
            },
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/ICredentialSchema"
              }
            }
          ]
        },
        "description": {
          "type": "string"
        },
        "expirationDate": {
          "type": "string"
        },
        "id": {
          "type": "string"
        },
        "issuanceDate": {
          "type": "string"
        },
        "issuer": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "$ref": "#/definitions/IIssuer"
            }
          ]
        },
        "name": {
          "type": "string"
        },
        "type": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "required": [
        "@context",
        "credentialSubject",
        "id",
        "issuanceDate",
        "issuer",
        "type"
      ],
      "additionalProperties": {
        "anyOf": [
          {},
          {}
        ]
      }
    },
    "ICredentialStatus": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
          "type": "string"
        }
      },
      "required": [
        "id",
        "type"
      ],
      "additionalProperties": false
    },
    "ICredentialSubject": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        }
      },
      "additionalProperties": {}
    },
    "ICredentialSchema": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
          "type": "string"
        }
      },
      "required": [
        "id",
        "type"
      ],
      "additionalProperties": false
    },
    "IIssuer": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        }
      },
      "required": [
        "id"
      ],
      "additionalProperties": {}
    },
    "IJsonLdVerifiableCredential": {
      "type": "object",
      "properties": {
        "proof": {
          "anyOf": [
            {
              "$ref": "#/definitions/IProof"
            },
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/IProof"
              }
            }
          ]
        },
        "@context": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "type": "string"
              }
            },
            {
              "type": "string"
            }
          ]
        },
        "credentialStatus": {
          "$ref": "#/definitions/ICredentialStatus"
        },
        "credentialSubject": {
          "$ref": "#/definitions/ICredentialSubject"
        },
        "credentialSchema": {
          "anyOf": [
            {
              "$ref": "#/definitions/ICredentialSchema"
            },
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/ICredentialSchema"
              }
            }
          ]
        },
        "description": {
          "type": "string"
        },
        "expirationDate": {
          "type": "string"
        },
        "id": {
          "type": "string"
        },
        "issuanceDate": {
          "type": "string"
        },
        "issuer": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "$ref": "#/definitions/IIssuer"
            }
          ]
        },
        "name": {
          "type": "string"
        },
        "type": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "required": [
        "@context",
        "credentialSubject",
        "id",
        "issuanceDate",
        "issuer",
        "proof",
        "type"
      ]
    },
    "PresentationSubmission": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "definition_id": {
          "type": "string"
        },
        "descriptor_map": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/Descriptor"
          }
        }
      },
      "required": [
        "id",
        "definition_id",
        "descriptor_map"
      ],
      "additionalProperties": false
    },
    "Descriptor": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "path": {
          "type": "string"
        },
        "path_nested": {
          "$ref": "#/definitions/Descriptor"
        },
        "format": {
          "type": "string"
        }
      },
      "required": [
        "id",
        "path",
        "format"
      ],
      "additionalProperties": false
    },
    "PresentationLocation": {
      "type": "string",
      "enum": [
        "vp_token",
        "id_token"
      ]
    }
  }
};
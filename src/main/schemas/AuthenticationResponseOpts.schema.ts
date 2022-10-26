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
        "id": {
          "type": "string"
        },
        "@context": {
          "anyOf": [
            {
              "$ref": "#/definitions/ICredentialContextType"
            },
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/ICredentialContextType"
              }
            }
          ]
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
    "ICredentialContextType": {
      "anyOf": [
        {
          "$ref": "#/definitions/ICredentialContext"
        },
        {
          "type": "string"
        }
      ]
    },
    "ICredentialContext": {
      "type": "object",
      "properties": {
        "name": {
          "type": "string"
        },
        "did": {
          "type": "string"
        }
      },
      "additionalProperties": {}
    },
    "IVerifiableCredential": {
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
        "expirationDate": {
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
        "issuanceDate": {
          "type": "string"
        },
        "credentialSubject": {
          "$ref": "#/definitions/ICredentialSubject"
        },
        "id": {
          "type": "string"
        },
        "@context": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/ICredentialContextType"
              }
            },
            {
              "$ref": "#/definitions/ICredentialContextType"
            }
          ]
        },
        "credentialStatus": {
          "$ref": "#/definitions/ICredentialStatus"
        },
        "credentialSchema": {
          "anyOf": [
            {
              "$ref": "#/definitions/ICredentialSchemaType"
            },
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/ICredentialSchemaType"
              }
            }
          ]
        },
        "description": {
          "type": "string"
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
        "issuanceDate",
        "issuer",
        "proof",
        "type"
      ]
    },
    "IProof": {
      "type": "object",
      "properties": {
        "type": {
          "anyOf": [
            {
              "$ref": "#/definitions/IProofType"
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
              "$ref": "#/definitions/IProofPurpose"
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
    "IProofType": {
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
    "IProofPurpose": {
      "type": "string",
      "enum": [
        "verificationMethod",
        "assertionMethod",
        "authentication",
        "keyAgreement",
        "contactAgreement",
        "capabilityInvocation",
        "capabilityDelegation"
      ]
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
    "ICredentialSubject": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        }
      },
      "additionalProperties": {}
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
    "ICredentialSchemaType": {
      "anyOf": [
        {
          "$ref": "#/definitions/ICredentialSchema"
        },
        {
          "type": "string"
        }
      ]
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
        "id"
      ],
      "additionalProperties": false
    },
    "PresentationSubmission": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string",
          "description": "A UUID or some other unique ID to identify this Presentation Submission"
        },
        "definition_id": {
          "type": "string",
          "description": "A UUID or some other unique ID to identify this Presentation Definition"
        },
        "descriptor_map": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/Descriptor"
          },
          "description": "List of descriptors of how the claims are being mapped to presentation definition"
        }
      },
      "required": [
        "id",
        "definition_id",
        "descriptor_map"
      ],
      "additionalProperties": false,
      "description": "It express how the inputs presented as proofs to a Verifier."
    },
    "Descriptor": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string",
          "description": "ID to identify the descriptor from Presentation Definition Input Descriptor it coresponds to."
        },
        "path": {
          "type": "string",
          "description": "The path where the verifiable credential is located in the presentation submission json"
        },
        "path_nested": {
          "$ref": "#/definitions/Descriptor"
        },
        "format": {
          "type": "string",
          "description": "The Proof or JWT algorith that the proof is in"
        }
      },
      "required": [
        "id",
        "path",
        "format"
      ],
      "additionalProperties": false,
      "description": "descriptor map laying out the structure of the presentation submission."
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
export const AuthenticationRequestOptsSchema = {
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$ref": "#/definitions/AuthenticationRequestOpts",
  "definitions": {
    "AuthenticationRequestOpts": {
      "type": "object",
      "properties": {
        "redirectUri": {
          "type": "string"
        },
        "requestBy": {
          "$ref": "#/definitions/ObjectBy"
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
              "$ref": "#/definitions/NoSignature"
            }
          ]
        },
        "responseMode": {
          "$ref": "#/definitions/ResponseMode"
        },
        "responseContext": {
          "$ref": "#/definitions/ResponseContext"
        },
        "claims": {
          "$ref": "#/definitions/OidcClaim"
        },
        "registration": {
          "$ref": "#/definitions/RequestRegistrationOpts"
        },
        "nonce": {
          "type": "string"
        },
        "state": {
          "type": "string"
        }
      },
      "required": [
        "redirectUri",
        "requestBy",
        "signatureType",
        "registration"
      ],
      "additionalProperties": false
    },
    "ObjectBy": {
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
        }
      },
      "required": [
        "type"
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
    "NoSignature": {
      "type": "object",
      "properties": {
        "hexPublicKey": {
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
        "hexPublicKey",
        "did"
      ],
      "additionalProperties": false
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
    "ResponseContext": {
      "type": "string",
      "enum": [
        "rp",
        "op",
        "wallet"
      ]
    },
    "OidcClaim": {
      "type": "object",
      "properties": {
        "vc": {
          "$ref": "#/definitions/OidcClaimRequest"
        }
      },
      "additionalProperties": {}
    },
    "OidcClaimRequest": {
      "type": "object",
      "additionalProperties": {
        "anyOf": [
          {
            "type": "null"
          },
          {
            "$ref": "#/definitions/OidcClaimJson"
          }
        ]
      }
    },
    "OidcClaimJson": {
      "type": "object",
      "properties": {
        "essential": {
          "type": "boolean"
        },
        "value": {
          "type": "string"
        },
        "values": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "additionalProperties": false
    },
    "RequestRegistrationOpts": {
      "type": "object",
      "properties": {
        "subjectIdentifiersSupported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/SubjectIdentifierType"
              }
            },
            {
              "$ref": "#/definitions/SubjectIdentifierType"
            }
          ]
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
        "credential_formats_supported": {
          "anyOf": [
            {
              "type": "array",
              "items": {
                "$ref": "#/definitions/CredentialType"
              }
            },
            {
              "$ref": "#/definitions/CredentialType"
            }
          ]
        },
        "registrationBy": {
          "$ref": "#/definitions/RegistrationType"
        }
      },
      "required": [
        "credential_formats_supported",
        "registrationBy",
        "subjectIdentifiersSupported"
      ],
      "additionalProperties": false
    },
    "SubjectIdentifierType": {
      "type": "string",
      "enum": [
        "jkt",
        "did"
      ]
    },
    "CredentialType": {
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
    }
  }
};
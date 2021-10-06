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
          "$ref": "#/definitions/ClaimOpts"
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
        "op"
      ]
    },
    "ClaimOpts": {
      "type": "object",
      "properties": {
        "presentationDefinitions": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/PresentationDefinitionWithLocation"
          }
        }
      },
      "additionalProperties": false
    },
    "PresentationDefinitionWithLocation": {
      "type": "object",
      "properties": {
        "location": {
          "$ref": "#/definitions/PresentationLocation"
        },
        "definition": {
          "$ref": "#/definitions/PresentationDefinition"
        }
      },
      "required": [
        "location",
        "definition"
      ],
      "additionalProperties": false
    },
    "PresentationLocation": {
      "type": "string",
      "enum": [
        "vp_token",
        "id_token"
      ]
    },
    "PresentationDefinition": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "purpose": {
          "type": "string"
        },
        "format": {
          "$ref": "#/definitions/Format"
        },
        "submission_requirements": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/SubmissionRequirement"
          }
        },
        "input_descriptors": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/InputDescriptor"
          }
        }
      },
      "required": [
        "id",
        "input_descriptors"
      ],
      "additionalProperties": false
    },
    "Format": {
      "type": "object",
      "properties": {
        "jwt": {
          "$ref": "#/definitions/JwtObject"
        },
        "jwt_vc": {
          "$ref": "#/definitions/JwtObject"
        },
        "jwt_vp": {
          "$ref": "#/definitions/JwtObject"
        },
        "ldp": {
          "$ref": "#/definitions/LdpObject"
        },
        "ldp_vc": {
          "$ref": "#/definitions/LdpObject"
        },
        "ldp_vp": {
          "$ref": "#/definitions/LdpObject"
        }
      },
      "additionalProperties": false
    },
    "JwtObject": {
      "type": "object",
      "properties": {
        "alg": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "required": [
        "alg"
      ],
      "additionalProperties": false
    },
    "LdpObject": {
      "type": "object",
      "properties": {
        "proof_type": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "required": [
        "proof_type"
      ],
      "additionalProperties": false
    },
    "SubmissionRequirement": {
      "type": "object",
      "properties": {
        "name": {
          "type": "string"
        },
        "purpose": {
          "type": "string"
        },
        "rule": {
          "$ref": "#/definitions/Rules"
        },
        "count": {
          "type": "number"
        },
        "min": {
          "type": "number"
        },
        "max": {
          "type": "number"
        },
        "from": {
          "type": "string"
        },
        "from_nested": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/SubmissionRequirement"
          }
        }
      },
      "required": [
        "rule"
      ],
      "additionalProperties": false
    },
    "Rules": {
      "type": "string",
      "enum": [
        "all",
        "pick"
      ]
    },
    "InputDescriptor": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "purpose": {
          "type": "string"
        },
        "group": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "schema": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/Schema"
          }
        },
        "constraints": {
          "$ref": "#/definitions/Constraints"
        }
      },
      "required": [
        "id",
        "schema"
      ],
      "additionalProperties": false
    },
    "Schema": {
      "type": "object",
      "properties": {
        "uri": {
          "type": "string"
        },
        "required": {
          "type": "boolean"
        }
      },
      "required": [
        "uri"
      ],
      "additionalProperties": false
    },
    "Constraints": {
      "type": "object",
      "properties": {
        "limit_disclosure": {
          "$ref": "#/definitions/Optionality"
        },
        "statuses": {
          "$ref": "#/definitions/Statuses"
        },
        "fields": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/Field"
          }
        },
        "subject_is_issuer": {
          "$ref": "#/definitions/Optionality"
        },
        "is_holder": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/HolderSubject"
          }
        },
        "same_subject": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/HolderSubject"
          }
        }
      },
      "additionalProperties": false
    },
    "Optionality": {
      "type": "string",
      "enum": [
        "required",
        "preferred"
      ]
    },
    "Statuses": {
      "type": "object",
      "properties": {
        "active": {
          "$ref": "#/definitions/PdStatus"
        },
        "suspended": {
          "$ref": "#/definitions/PdStatus"
        },
        "revoked": {
          "$ref": "#/definitions/PdStatus"
        }
      },
      "additionalProperties": false
    },
    "PdStatus": {
      "type": "object",
      "properties": {
        "directive": {
          "$ref": "#/definitions/Directives"
        }
      },
      "additionalProperties": false
    },
    "Directives": {
      "type": "string",
      "enum": [
        "required",
        "allowed",
        "disallowed"
      ]
    },
    "Field": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "path": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "purpose": {
          "type": "string"
        },
        "filter": {
          "$ref": "#/definitions/Filter"
        },
        "predicate": {
          "$ref": "#/definitions/Optionality"
        }
      },
      "additionalProperties": false
    },
    "Filter": {
      "type": "object",
      "properties": {
        "type": {
          "type": "string"
        },
        "format": {
          "type": "string"
        },
        "pattern": {
          "type": "string"
        },
        "minLength": {
          "type": "number"
        },
        "maxLength": {
          "type": "number"
        },
        "minimum": {
          "type": "number"
        },
        "exclusiveMinimum": {
          "type": "number"
        },
        "exclusiveMaximum": {
          "type": "number"
        },
        "maximum": {
          "type": "number"
        },
        "_const": {
          "type": "number"
        },
        "_enum": {
          "type": "array",
          "items": {
            "type": "number"
          }
        },
        "not": {
          "type": "object"
        }
      },
      "required": [
        "type"
      ],
      "additionalProperties": false
    },
    "HolderSubject": {
      "type": "object",
      "properties": {
        "field_id": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "directive": {
          "$ref": "#/definitions/Optionality"
        }
      },
      "required": [
        "field_id",
        "directive"
      ],
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
        "registrationBy": {
          "$ref": "#/definitions/RegistrationType"
        }
      },
      "required": [
        "credentialFormatsSupported",
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
    }
  }
};
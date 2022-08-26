export const RPRegistrationMetadataPayloadSchema = {
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$ref": "#/definitions/RPRegistrationMetadataPayload",
  "definitions": {
    "RPRegistrationMetadataPayload": {
      "type": "object",
      "properties": {
        "id_token_signing_alg_values_supported": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/SigningAlgo"
          }
        },
        "id_token_types_supported": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/IdTokenType"
          }
        },
        "request_object_signing_alg_values_supported": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/SigningAlgo"
          }
        },
        "response_types_supported": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/ResponseType"
          }
        },
        "scopes_supported": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/Scope"
          }
        },
        "subject_syntax_types_supported": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "subject_types_supported": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/SubjectType"
          }
        },
        "vp_formats": {
          "$ref": "#/definitions/Format"
        }
      },
      "required": [
        "id_token_signing_alg_values_supported",
        "request_object_signing_alg_values_supported",
        "response_types_supported",
        "scopes_supported",
        "subject_syntax_types_supported",
        "subject_types_supported",
        "vp_formats"
      ],
      "additionalProperties": false
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
    "IdTokenType": {
      "type": "string",
      "enum": [
        "subject_signed",
        "attester_signed"
      ]
    },
    "ResponseType": {
      "type": "string",
      "enum": [
        "id_token",
        "vp_token"
      ]
    },
    "Scope": {
      "type": "string",
      "enum": [
        "openid",
        "openid did_authn",
        "profile",
        "email",
        "address",
        "phone"
      ]
    },
    "SubjectType": {
      "type": "string",
      "enum": [
        "public",
        "pairwise"
      ]
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
    }
  }
};
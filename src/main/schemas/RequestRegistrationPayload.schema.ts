export const RequestRegistrationPayloadSchema = {
  "$ref": "#/definitions/RequestRegistrationPayload",
  "$schema": "http://json-schema.org/draft-07/schema#",
  "definitions": {
    "Format": {
      "additionalProperties": false,
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
      "type": "object"
    },
    "IdTokenType": {
      "enum": [
        "attester_signed",
        "subject_signed"
      ],
      "type": "string"
    },
    "JwtObject": {
      "additionalProperties": false,
      "properties": {
        "alg": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "required": [
        "alg"
      ],
      "type": "object"
    },
    "LdpObject": {
      "additionalProperties": false,
      "properties": {
        "proof_type": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "required": [
        "proof_type"
      ],
      "type": "object"
    },
    "RPRegistrationMetadataPayload": {
      "additionalProperties": false,
      "properties": {
        "id_token_signing_alg_values_supported": {
          "items": {
            "$ref": "#/definitions/SigningAlgo"
          },
          "type": "array"
        },
        "id_token_types_supported": {
          "items": {
            "$ref": "#/definitions/IdTokenType"
          },
          "type": "array"
        },
        "request_object_signing_alg_values_supported": {
          "items": {
            "$ref": "#/definitions/SigningAlgo"
          },
          "type": "array"
        },
        "response_types_supported": {
          "items": {
            "$ref": "#/definitions/ResponseType"
          },
          "type": "array"
        },
        "scopes_supported": {
          "items": {
            "$ref": "#/definitions/Scope"
          },
          "type": "array"
        },
        "subject_syntax_types_supported": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "subject_types_supported": {
          "items": {
            "$ref": "#/definitions/SubjectType"
          },
          "type": "array"
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
      "type": "object"
    },
    "RequestRegistrationPayload": {
      "additionalProperties": false,
      "properties": {
        "registration": {
          "$ref": "#/definitions/RPRegistrationMetadataPayload"
        },
        "registration_uri": {
          "type": "string"
        }
      },
      "type": "object"
    },
    "ResponseType": {
      "enum": [
        "id_token",
        "vp_token"
      ],
      "type": "string"
    },
    "Scope": {
      "enum": [
        "address",
        "email",
        "openid",
        "openid did_authn",
        "phone",
        "profile"
      ],
      "type": "string"
    },
    "SigningAlgo": {
      "enum": [
        "ES256",
        "ES256K",
        "EdDSA",
        "RS256",
        "none"
      ],
      "type": "string"
    },
    "SubjectType": {
      "enum": [
        "pairwise",
        "public"
      ],
      "type": "string"
    }
  }
};
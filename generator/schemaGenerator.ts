import fs from 'fs';
import {
  BaseType,
  createFormatter,
  createParser,
  createProgram,
  Definition,
  FunctionType,
  MutableTypeFormatter,
  SchemaGenerator,
  SubTypeFormatter
} from 'ts-json-schema-generator';
import { Schema } from 'ts-json-schema-generator/src/Schema/Schema';

class CustomTypeFormatter implements SubTypeFormatter {
  public supportsType(type: FunctionType): boolean {
    return type instanceof FunctionType;
  }

  public getDefinition(): Definition {
    // Return a custom schema for the function property.
    return {
      type: 'object',
      properties: {
        isFunction: {
          type: 'boolean',
          const: true
        }
      }
    };
  }

  public getChildren(): BaseType[] {
    return [];
  }
}

function writeSchema(config, sorted: boolean) {
  const formatter = createFormatter(config, (fmt: MutableTypeFormatter) => {
    fmt.addTypeFormatter(new CustomTypeFormatter());
  });

  const program = createProgram(config);
  let schema: Schema = new SchemaGenerator(program, createParser(program, config), formatter, config).createSchema(config.type);

  if (sorted) {
    schema = jsonSort(schema);
  }

  let schemaString = JSON.stringify(schema, null, 2);
  schemaString = correctSchema(schemaString);

  fs.writeFile(config.outputPath, `export const ${config.outputConstName} = ${schemaString};`, (err) => {
    if (err) throw err;
  });
}

function isObject(v) {
  return '[object Object]' === Object.prototype.toString.call(v);
};

function jsonSort(o: Schema) {
  if (Array.isArray(o)) {
    return o.sort().map(jsonSort);
  } else if (isObject(o)) {
    return Object
    .keys(o)
    .sort()
    .reduce(function(a, k) {
      a[k] = jsonSort(o[k]);

      return a;
    }, {});
  }

  return o;
}

function correctSchema(schemaString: string) {
  return schemaString.replace(
    '"SuppliedSignature": {\n' +
    '      "type": "object",\n' +
    '      "properties": {\n' +
    '        "signature": {\n' +
    '          "type": "object",\n' +
    '          "properties": {\n' +
    '            "isFunction": {\n' +
    '              "type": "boolean",\n' +
    '              "const": true\n' +
    '            }\n' +
    '          }\n' +
    '        },\n' +
    '        "did": {\n' +
    '          "type": "string"\n' +
    '        },\n' +
    '        "kid": {\n' +
    '          "type": "string"\n' +
    '        }\n' +
    '      },\n' +
    '      "required": [\n' +
    '        "signature",\n' +
    '        "did",\n' +
    '        "kid"\n' +
    '      ],\n' +
    '      "additionalProperties": false\n' +
    '    },',
    '"SuppliedSignature": {\n' +
    '      "type": "object",\n' +
    '      "properties": {\n' +
    '        "did": {\n' +
    '          "type": "string"\n' +
    '        },\n' +
    '        "kid": {\n' +
    '          "type": "string"\n' +
    '        }\n' +
    '      },\n' +
    '      "required": [\n' +
    '        "did",\n' +
    '        "kid"\n' +
    '      ],\n' +
    '      "additionalProperties": true\n' +
    '    },');
}

const requestOptsConf = {
  path: '../src/main/types/SIOP.types.ts',
  tsconfig: 'tsconfig.json',
  type: 'AuthenticationRequestOpts', // Or <type-name> if you want to generate schema for that one type only
  outputPath: 'src/main/schemas/AuthenticationRequestOpts.schema.ts',
  outputConstName: 'AuthenticationRequestOptsSchema',
  skipTypeCheck: true
};

const responseOptsConf = {
  path: '../src/main/types/SIOP.types.ts',
  tsconfig: 'tsconfig.json',
  type: 'AuthenticationResponseOpts', // Or <type-name> if you want to generate schema for that one type only
  outputPath: 'src/main/schemas/AuthenticationResponseOpts.schema.ts',
  outputConstName: 'AuthenticationResponseOptsSchema',
  skipTypeCheck: true
};

const authenticationResponsePayload = {
  path: '../src/main/types/SIOP.types.ts',
  tsconfig: 'tsconfig.json',
  type: 'AuthenticationResponsePayload',
  outputPath: 'src/main/schemas/AuthenticationResponsePayload.schema.ts',
  outputConstName: 'AuthenticationResponsePayloadSchema',
  skipTypeCheck: true
};

const requestRegistrationPayload = {
  path: '../src/main/types/SIOP.types.ts',
  tsconfig: 'tsconfig.json',
  type: 'RequestRegistrationPayload',
  outputPath: 'src/main/schemas/RequestRegistrationPayload.schema.ts',
  outputConstName: 'RequestRegistrationPayloadSchema',
  skipTypeCheck: true
};

writeSchema(requestOptsConf, false);
writeSchema(responseOptsConf, false);
writeSchema(authenticationResponsePayload, true);
writeSchema(requestRegistrationPayload, true);

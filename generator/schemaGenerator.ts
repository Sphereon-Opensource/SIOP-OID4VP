import fs from 'fs';
import {
  createFormatter,
  createParser,
  createProgram, MutableTypeFormatter,
  SchemaGenerator,
  BaseType,
  Definition,
  FunctionType,
  SubTypeFormatter
} from 'ts-json-schema-generator';

class CustomTypeFormatter implements SubTypeFormatter {
  public supportsType(type: FunctionType): boolean {
    return type instanceof FunctionType;
  }

  public getDefinition(): Definition {
    // Return a custom schema for the function property.
    return {
      properties: {
        isFunction: {
          type: "boolean",
          const: true,
        },
      },
    };
  }

  public getChildren(): BaseType[] {
    return [];
  }
}

function writeSchema(config) {
  const formatter = createFormatter(config, (fmt: MutableTypeFormatter) => {
    fmt.addTypeFormatter(new CustomTypeFormatter());
  });

  const program = createProgram(config);
  const schema = new SchemaGenerator(program, createParser(program, config), formatter, config).createSchema(config.type);

  let schemaString = JSON.stringify(schema, null, 2);
  schemaString = correctSchema(schemaString)

  fs.writeFile(config.outputPath, `export const ${config.outputConstName} = ${schemaString};`, (err) => {
    if (err) throw err;
  });
}

function correctSchema(schemaString: string) {
  return schemaString.replace(
    "\"SuppliedSignature\": {\n" +
    "      \"type\": \"object\",\n" +
    "      \"properties\": {\n" +
    "        \"signature\": {\n" +
    "          \"type\": \"object\",\n" +
    "          \"properties\": {\n" +
    "            \"isFunction\": {\n" +
    "              \"type\": \"boolean\",\n" +
    "              \"const\": true\n" +
    "            }\n" +
    "          }\n" +
    "        },\n" +
    "        \"did\": {\n" +
    "          \"type\": \"string\"\n" +
    "        },\n" +
    "        \"kid\": {\n" +
    "          \"type\": \"string\"\n" +
    "        }\n" +
    "      },\n" +
    "      \"required\": [\n" +
    "        \"signature\",\n" +
    "        \"did\",\n" +
    "        \"kid\"\n" +
    "      ],\n" +
    "      \"additionalProperties\": false\n" +
    "    },",
    "\"SuppliedSignature\": {\n" +
    "      \"type\": \"object\",\n" +
    "      \"properties\": {\n" +
    "        \"did\": {\n" +
    "          \"type\": \"string\"\n" +
    "        },\n" +
    "        \"kid\": {\n" +
    "          \"type\": \"string\"\n" +
    "        }\n" +
    "      },\n" +
    "      \"required\": [\n" +
    "        \"did\",\n" +
    "        \"kid\"\n" +
    "      ],\n" +
    "      \"additionalProperties\": true\n" +
    "    },")
}

const requestOptsConf = {
  path: "../src/main/types/SIOP.types.ts",
  tsconfig: "tsconfig.json",
  type: "AuthenticationRequestOpts", // Or <type-name> if you want to generate schema for that one type only
  outputPath: "src/main/schemas/AuthenticationRequestOpts.schema.ts",
  outputConstName: "AuthenticationRequestOptsSchema",
  skipTypeCheck: true
};


const responseOptsConf = {
  path: "../src/main/types/SIOP.types.ts",
  tsconfig: "tsconfig.json",
  type: "AuthenticationResponseOpts", // Or <type-name> if you want to generate schema for that one type only
  outputPath: "src/main/schemas/AuthenticationResponseOpts.schema.ts",
  outputConstName: "AuthenticationResponseOptsSchema",
  skipTypeCheck: true
};

const rPRegistrationMetadataPayload = {
  path: '../src/main/types/SIOP.types.ts',
  tsconfig: 'tsconfig.json',
  type: 'RPRegistrationMetadataPayload',
  outputPath: 'src/main/schemas/RPRegistrationMetadataPayload.schema.ts',
  outputConstName: 'RPRegistrationMetadataPayloadSchema',
  skipTypeCheck: true
};

const discoveryMetadataPayload = {
  path: '../src/main/types/SIOP.types.ts',
  tsconfig: 'tsconfig.json',
  type: 'DiscoveryMetadataPayload',
  outputPath: 'src/main/schemas/DiscoveryMetadataPayload.schema.ts',
  outputConstName: 'DiscoveryMetadataPayloadSchema',
  skipTypeCheck: true
};

const id1AuthenticationRequestPayload = {
  path: "../src/main/types/SIOP.types.ts",
  tsconfig: "tsconfig.json",
  type: "ID1AuthenticationRequestPayload", // Or <type-name> if you want to generate schema for that one type only
  outputPath: "src/main/schemas/ID1AuthenticationRequestPayload.schema.ts",
  outputConstName: "ID1AuthenticationRequestPayloadSchema",
  skipTypeCheck: true
};

const d11AuthenticationRequestPayload = {
  path: "../src/main/types/SIOP.types.ts",
  tsconfig: "tsconfig.json",
  type: "D11AuthenticationRequestPayload", // Or <type-name> if you want to generate schema for that one type only
  outputPath: "src/main/schemas/D11AuthenticationRequestPayload.schema.ts",
  outputConstName: "D11AuthenticationRequestPayloadSchema",
  skipTypeCheck: true
}

writeSchema(id1AuthenticationRequestPayload)
writeSchema(d11AuthenticationRequestPayload)
writeSchema(requestOptsConf);
writeSchema(responseOptsConf);
writeSchema(rPRegistrationMetadataPayload);
writeSchema(discoveryMetadataPayload);

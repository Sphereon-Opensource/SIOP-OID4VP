// main.js

const fs = require("fs");

const tsj = require("ts-json-schema-generator");

const config = {
    path: "../src/types/SIOP.types.ts",
    tsconfig: "tsconfig.json",
    type: "AuthenticationRequestOpts", // Or <type-name> if you want to generate schema for that one type only
};

const output_path = "src/schemas/AuthenticationRequestOpts.schema.ts";

const schema = tsj.createGenerator(config).createSchema(config.type);
const schemaString = JSON.stringify(schema, null, 2);
fs.writeFile(output_path, `export const AuthenticationRequestOptsSchema = ${schemaString};`, (err) => {
    if (err) throw err;
});

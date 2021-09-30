const fs = require("fs");
const tsj = require("ts-json-schema-generator");

function writeSchema(config) {
    const schema = tsj.createGenerator(config).createSchema(config.type);
    const schemaString = JSON.stringify(schema, null, 2);
    fs.writeFile(config.outputPath, `export const ${config.outputConstName} = ${schemaString};`, (err) => {
        if (err) throw err;
    });
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

writeSchema(requestOptsConf);
writeSchema(responseOptsConf);

import {fetch} from "cross-fetch";

import {ResponseOpts} from "../types/DidAuth-types";
import {JWTPayload} from "../types/JWT-types";
import {DIDDocument} from "../types/SSI-Types";

export async function postWithBearerToken(
    url: string,
    body: JWTPayload,
    bearerToken: string
): Promise<Response> {
    try {

        const response = await fetch(url, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${bearerToken}`
            },
            body: JSON.stringify(body),
        });
        if (!response ||
            !response.status ||
            (response.status !== 200 && response.status !== 201)) {
            throw new Error(`Received unexpected respons status ${response.status}:${response.statusText}, ${await response.text()}`);
        }
        return response;

    } catch (error) {
        throw new Error(`${(error as Error).message}`);
    }
}

export async function fetchDidDocument(opts: ResponseOpts): Promise<DIDDocument> {
    const response = await fetch(opts.registrationType.referenceUri);
    if (!response) {
        throw new Error("ERROR_RETRIEVING_DID_DOCUMENT");
    }
    const json = await response.json();
    const didDoc = json as DIDDocument;
    if (!didDoc.verificationMethod && !didDoc.verificationMethod[0] && !didDoc.verificationMethod[0].publicKeyJwk) {
        throw new Error("ERROR_RETRIEVING_DID_DOCUMENT");
    }
    return didDoc;
}

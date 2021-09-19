import {getResolver as getUniResolver} from '@sphereon/did-uni-client/dist/resolver/Resolver';
import Ajv from 'ajv';
import {Resolvable, Resolver} from 'did-resolver';

import AuthenticationRequest from './AuthenticationRequest';
import {DIDJwt, State} from './functions';
import {AuthenticationRequestOptsSchema} from './schemas/AuthenticationRequestOpts.schema';
import {SIOP} from './types';
import {
    AuthenticationRequestOpts,
    AuthenticationRequestURI,
    ExternalSignature,
    InternalSignature,
    NoSignature,
    ObjectBy,
    PassBy,
    RequestRegistrationOpts,
    ResponseContext,
    ResponseMode,
    SubjectIdentifierType,
} from './types/SIOP.types';
import {OidcClaim} from './types/SSI.types';

const ajv = new Ajv();
const validate = ajv.compile(AuthenticationRequestOptsSchema);

export class RP {
    // private readonly didMethods: string[];
    // private readonly resolvers: Map<string, Resolvable> = new Map<string, Resolvable>();
    private readonly authRequestOpts: AuthenticationRequestOpts;

    private constructor(opts: { builder?: RP.Builder; requestOpts?: AuthenticationRequestOpts }) {
        // this.didMethods = builder.didMethods;
        // this.resolvers = builder.resolvers;
        const requestOpts: AuthenticationRequestOpts = opts.builder
            ? {
                registration: opts.builder.requestRegistration as RequestRegistrationOpts,
                redirectUri: opts.builder.redirectUri,
                requestBy: opts.builder.requestBy,
                signatureType: opts.builder.signatureType,
                responseMode: opts.builder.responseMode,
                responseContext: opts.builder.responseContext,
            }
            : opts.requestOpts;

        const valid = validate(requestOpts);
        if (!valid) {
            throw new Error('RP builder validation error: ' + JSON.stringify(validate.errors));
        }
        // createCheckers(<ITypeSuite>AuthenticationRequestOpts)
        this.authRequestOpts = {...requestOpts};
    }

    public createAuthenticationRequest(opts?: { nonce?: string; state?: string }): Promise<AuthenticationRequestURI> {
        return AuthenticationRequest.createURI(this.newAuthenticationRequestOpts(opts));
    }

    public newAuthenticationRequestOpts(opts?: { nonce?: string; state?: string }): AuthenticationRequestOpts {
        const state = State.getState(opts?.state);
        const nonce = State.getNonce(state, opts?.nonce);
        return {
            ...this.authRequestOpts,
            state,
            nonce,
        };
    }

    public static fromRequestOpts(opts: SIOP.AuthenticationRequestOpts): RP {
        return new RP({requestOpts: opts});
    }

    public static Builder = class {
        subjectIdentifierTypes: SubjectIdentifierType = SubjectIdentifierType.DID;
        didMethods: string[] = [];
        resolvers: Map<string, Resolvable> = new Map<string, Resolvable>();

        requestRegistration: Partial<RequestRegistrationOpts> = {};
        redirectUri: string;
        requestBy: ObjectBy;
        signatureType: InternalSignature | ExternalSignature | NoSignature;
        responseMode?: ResponseMode;
        responseContext?: ResponseContext.RP;
        claims?: OidcClaim;

        addResolver(didMethod: string, resolver: Resolvable): RP.Builder {
            this.didMethods.push(DIDJwt.toSIOPRegistrationDidMethod(didMethod));
            this.resolvers.set(DIDJwt.getMethodFromDid(didMethod), resolver);
            return this;
        }

        addDidMethod(didMethod: string): RP.Builder {
            this.addResolver(didMethod, new Resolver(getUniResolver(DIDJwt.getMethodFromDid(didMethod))));
            return this;
        }

        redirect(redirectUri: string): RP.Builder {
            this.redirectUri = redirectUri;
            return this;
        }

        requestRef(type: PassBy, referenceUri?: string): RP.Builder {
            this.requestBy = {
                type,
                referenceUri,
            };
            return this;
        }

        response(responseMode: ResponseMode): RP.Builder {
            this.responseMode = responseMode;
            return this;
        }

        registrationRef(registrationBy: PassBy, refUri?: string): RP.Builder {
            this.requestRegistration = {
                registrationBy: {
                    type: registrationBy,
                },
            };
            if (refUri) {
                this.requestRegistration.registrationBy.referenceUri = refUri;
            }
            return this;
        }

        // Only internal supported for now
        signature(signatureType: InternalSignature): RP.Builder {
            this.signatureType = signatureType;
            return this;
        }

        internalSignature(hexPrivateKey: string, did: string, kid?: string): RP.Builder {
            this.signature({hexPrivateKey, did, kid});
            return this;
        }

        build(): RP {
            this.requestRegistration.didMethodsSupported = this.didMethods;
            this.requestRegistration.subjectIdentifiersSupported = this.subjectIdentifierTypes;
            return new RP({builder: this});
        }
    };
}

// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace RP {
    export type Builder = InstanceType<typeof RP.Builder>;
}

import {Resolvable} from "./DidAuth";


export interface AgentResponse {

}

export declare class Agent {
    #private;
    resolver: Resolvable;
    constructor(opts?: {
        privateKey: string;
        resolver: Resolvable;
    });

    verifyAuthResponse(response: AgentResponse, nonce: string): Promise<string>;
}
export default Agent;

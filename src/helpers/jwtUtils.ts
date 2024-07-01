import { jwtDecode } from 'jwt-decode';

import { JwtHeader, JwtPayload, ResponseIss, SIOPErrors } from '../types';

export function parseJWT(jwt: string) {
  const header = jwtDecode<JwtHeader & { x5c?: string[]; jwk?: JsonWebKey }>(jwt, { header: true });
  const payload = jwtDecode<JwtPayload>(jwt, { header: false });

  if (!payload || !header) {
    throw new Error(SIOPErrors.NO_JWT);
  }
  return { header, payload };
}

export function isIssSelfIssued(payload: JwtPayload): boolean {
  if (!payload.iss) throw new Error(SIOPErrors.NO_ISS_DID);
  return payload.iss.includes(ResponseIss.SELF_ISSUED_V1) || payload.iss.includes(ResponseIss.SELF_ISSUED_V2) || payload.iss === payload.sub;
}

export function getSubDidFromPayload(payload: JwtPayload, header?: JwtHeader): string {
  if (isIssSelfIssued(payload) && payload.sub.startsWith('did:')) {
    let did;
    if (payload.sub && payload.sub.startsWith('did:')) {
      did = payload.sub;
    }
    if (!did && header && header.kid && header.kid.startsWith('did:')) {
      did = header.kid.split('#')[0];
    }
    if (did) {
      return did;
    }
  }
  return payload.sub;
}

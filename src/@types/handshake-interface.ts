import type { bytes } from './basic';
import type { NoiseSession } from './handshake';

export interface IHandshake {
  session: NoiseSession
  encrypt: (plaintext: bytes, session: NoiseSession) => bytes
  decrypt: (ciphertext: bytes, session: NoiseSession, dst?: Uint8Array) => { plaintext: bytes, valid: boolean }

  getRemoteStaticKey: () => bytes
}

export interface HandshakeHandler {
  beforeWriteMessage: (session: NoiseSession) => Promise<Uint8Array | null>;
  onReadMessage: (session: NoiseSession, payload: Uint8Array) => Promise<boolean>;
}

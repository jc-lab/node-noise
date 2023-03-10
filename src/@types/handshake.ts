import type { bytes, bytes32, uint64 } from './basic';
import type { KeyPair } from './keypair';
import type { Nonce } from '../nonce';

export type Hkdf = [bytes, bytes, bytes]

export interface MessageBuffer {
  ne: bytes32
  ns: bytes
  ciphertext: bytes
}

export interface CipherState {
  k: bytes32
  // For performance reasons, the nonce is represented as a Nonce object
  // The nonce is treated as a uint64, even though the underlying `number` only has 52 safely-available bits.
  n: Nonce
}

export interface SymmetricState {
  cs: CipherState
  ck: bytes32 // chaining key
  h: bytes32 // handshake hash
}

export interface HandshakeState {
  ss: SymmetricState
  s: KeyPair
  e: KeyPair | null
  rs: bytes32 | null
  re: bytes32 | null
  psk: bytes32 | null
}

export enum Action {
  READ_MESSAGE,
  WRITE_MESSAGE,
  SPLIT
}

export interface NoiseSession {
  hs: HandshakeState
  h?: bytes32
  cs1?: CipherState
  cs2?: CipherState
  mc: uint64
  i: boolean

  action: Action
  patternIndex: number
}

export interface INoisePayload {
  identityKey: bytes
  identitySig: bytes
  data: bytes
}

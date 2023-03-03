import type { bytes32 } from './basic';

export interface KeyPair {
  publicKey: bytes32
  privateKey: bytes32
}

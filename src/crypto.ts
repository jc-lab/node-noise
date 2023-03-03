import type { bytes32, bytes } from './@types/basic';
import type { Hkdf } from './@types/handshake';
import type { KeyPair } from './@types/keypair';

export interface ICryptoInterface {
  hashSHA256: (data: Uint8Array) => Uint8Array

  getHKDF: (ck: bytes32, ikm: Uint8Array) => Hkdf

  generateX25519KeyPair: () => KeyPair
  generateX25519KeyPairFromSeed: (seed: Uint8Array) => KeyPair
  generateX25519SharedKey: (privateKey: Uint8Array, publicKey: Uint8Array) => Uint8Array

  chaCha20Poly1305Encrypt: (plaintext: Uint8Array, nonce: Uint8Array, ad: Uint8Array, k: bytes32) => bytes
  chaCha20Poly1305Decrypt: (ciphertext: Uint8Array, nonce: Uint8Array, ad: Uint8Array, k: bytes32, dst?: Uint8Array) => bytes | null
}

import type { bytes } from './@types/basic';
// import { unmarshalPublicKey, unmarshalPrivateKey } from '@libp2p/crypto/keys'
// import type { PeerId } from '@libp2p/interface-peer-id'
// import { peerIdFromKeys } from '@libp2p/peer-id'
// import { concat as uint8ArrayConcat } from 'uint8arrays/concat'
// import { fromString as uint8ArrayFromString } from 'uint8arrays/from-string'
// import { NoiseExtensions, NoiseHandshakePayload } from './proto/payload'
//
// export async function getPayload (
//   localPeer: PeerId,
//   staticPublicKey: bytes,
//   extensions?: NoiseExtensions
// ): Promise<bytes> {
//   const signedPayload = await signPayload(localPeer, getHandshakePayload(staticPublicKey))
//
//   if (localPeer.publicKey == null) {
//     throw new Error('PublicKey was missing from local PeerId')
//   }
//
//   return createHandshakePayload(
//     localPeer.publicKey,
//     signedPayload,
//     extensions
//   )
// }
//
// export function createHandshakePayload (
//   libp2pPublicKey: Uint8Array,
//   signedPayload: Uint8Array,
//   extensions?: NoiseExtensions
// ): bytes {
//   return NoiseHandshakePayload.encode({
//     identityKey: libp2pPublicKey,
//     identitySig: signedPayload,
//     extensions: extensions ?? { webtransportCerthashes: [] }
//   }).subarray()
// }
//
// export async function signPayload (privateKeyInput: bytes, payload: bytes): Promise<bytes> {
//   const privateKey = await unmarshalPrivateKey(privateKeyInput)
//
//   return await privateKey.sign(payload)
// }
//
// export async function getPeerIdFromPayload (payload: NoiseHandshakePayload): Promise<PeerId> {
//   return await peerIdFromKeys(payload.identityKey)
// }
//
// export function decodePayload (payload: bytes | Uint8Array): NoiseHandshakePayload {
//   return NoiseHandshakePayload.decode(payload)
// }
//
// /**
//  * Verifies signed payload, throws on any irregularities.
//  *
//  * @param {bytes} noiseStaticKey - owner's noise static key
//  * @param {bytes} payload - decoded payload
//  * @param {PeerId} remotePeer - owner's libp2p peer ID
//  * @returns {Promise<PeerId>} - peer ID of payload owner
//  */
// export async function verifySignedPayload (
//   publicKeyRaw: bytes,
//   receivedPayload: bytes,
//   noiseStaticKey: bytes,
//   payload: NoiseHandshakePayload,
//   remotePeer: PeerId
// ): Promise<PeerId> {
//   // Unmarshaling from PublicKey protobuf
//   const payloadPeerId = await peerIdFromKeys(payload.identityKey)
//   if (!payloadPeerId.equals(remotePeer)) {
//     throw new Error('Peer ID doesn\'t match libp2p public key.')
//   }
//   const generatedPayload = getHandshakePayload(noiseStaticKey)
//
//   if (payloadPeerId.publicKey == null) {
//     throw new Error('PublicKey was missing from PeerId')
//   }
//
//   if (payload.identitySig == null) {
//     throw new Error('Signature was missing from message')
//   }
//
//   const publicKey = unmarshalPublicKey(publicKeyRaw)
//
//   const valid = await publicKey.verify(generatedPayload, payload.identitySig)
//
//   if (!valid) {
//     throw new Error('Static key doesn\'t match to peer that signed payload!')
//   }
//
//   return payloadPeerId
// }

export function isValidPublicKey (pk: bytes): boolean {
  if (!(pk instanceof Uint8Array)) {
    return false;
  }

  if (pk.length !== 32) {
    return false;
  }

  return true;
}

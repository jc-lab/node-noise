import debug from 'debug';

// import { toString as uint8ArrayToString } from './uint8arrays/to-string'
import type { NoiseSession } from './@types/handshake';
import type { KeyPair } from './@types/keypair';
import { DUMP_SESSION_KEYS } from './constants';

export interface Logger {
  (formatter: any, ...args: any[]): void
  error: (formatter: any, ...args: any[]) => void
  trace: (formatter: any, ...args: any[]) => void
  enabled: boolean
}

export function xlogger (name: string): Logger {
  return Object.assign(debug(name), {
    error: debug(`${name}:error`),
    trace: debug(`${name}:trace`)
  });
}

const log = xlogger('libp2p:noise');

export { log as logger };

let keyLogger: Logger;
if (DUMP_SESSION_KEYS) {
  keyLogger = log;
} else {
  keyLogger = Object.assign(() => { /* do nothing */ }, {
    enabled: false,
    trace: () => {},
    error: () => {}
  });
}

function uint8ArrayToString(a: Uint8Array, enc: BufferEncoding): string {
  return Buffer.from(a).toString(enc);
}

export function logLocalStaticKeys (s: KeyPair): void {
  keyLogger(`LOCAL_STATIC_PUBLIC_KEY ${uint8ArrayToString(s.publicKey, 'hex')}`);
  keyLogger(`LOCAL_STATIC_PRIVATE_KEY ${uint8ArrayToString(s.privateKey, 'hex')}`);
}

export function logLocalEphemeralKeys (e: KeyPair|undefined): void {
  if (e) {
    keyLogger(`LOCAL_PUBLIC_EPHEMERAL_KEY ${uint8ArrayToString(e.publicKey, 'hex')}`);
    keyLogger(`LOCAL_PRIVATE_EPHEMERAL_KEY ${uint8ArrayToString(e.privateKey, 'hex')}`);
  } else {
    keyLogger('Missing local ephemeral keys.');
  }
}

export function logRemoteStaticKey (rs: Uint8Array): void {
  keyLogger(`REMOTE_STATIC_PUBLIC_KEY ${uint8ArrayToString(rs, 'hex')}`);
}

export function logRemoteEphemeralKey (re: Uint8Array): void {
  keyLogger(`REMOTE_EPHEMERAL_PUBLIC_KEY ${uint8ArrayToString(re, 'hex')}`);
}

export function logCipherState (session: NoiseSession): void {
  if (session.cs1 && session.cs2) {
    keyLogger(`CIPHER_STATE_1 ${session.cs1.n.getUint64()} ${uint8ArrayToString(session.cs1.k, 'hex')}`);
    keyLogger(`CIPHER_STATE_2 ${session.cs2.n.getUint64()} ${uint8ArrayToString(session.cs2.k, 'hex')}`);
  } else {
    keyLogger('Missing cipher state.');
  }
}

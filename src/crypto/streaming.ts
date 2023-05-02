import * as streams from 'stream';
import { TAG_LENGTH } from '@stablelib/chacha20poly1305';
import type { IHandshake } from '../@types/handshake-interface';
import type { MetricsRegistry } from '../metrics';
import { uint16BEEncode } from '../encoder';

const doImmediate = (typeof setImmediate !== 'undefined') ? setImmediate : (fn: any) => {
  setTimeout(fn, 0);
};

// Returns generator that encrypts payload from the user
export function encryptStream (handshake: IHandshake, metrics?: MetricsRegistry, noLengthCodec?: boolean, noiseMsgMaxLengthBytes?: number): streams.Duplex {
  const maxLengthBytes = noiseMsgMaxLengthBytes || -1;
  const maxLengthBytesWithoutTag = maxLengthBytes - 16;
  let nextWrite: Function | null = null;

  return new streams.Transform({
    autoDestroy: true,
    read(size: number) {
      const nextWriteLocal = nextWrite;
      if (nextWriteLocal) {
        nextWrite = null;
        nextWriteLocal();
      }
    },
    write(chunk: any, encoding: BufferEncoding, callback: (err?: any) => void): void {
      let i = 0;
      const next = () => {
        let end = chunk.length;
        if (i < chunk.length) {
          if (maxLengthBytesWithoutTag > 0) {
            end = i + maxLengthBytesWithoutTag;
            if (end > chunk.length) {
              end = chunk.length;
            }
          }

          const plaintext = chunk.subarray(i, end);
          const data = Buffer.from(handshake.encrypt(plaintext, handshake.session));
          metrics?.encryptedPackets.increment();

          if (!noLengthCodec) {
            const encodedLength = uint16BEEncode(data.byteLength);
            this.push(encodedLength);
          }
          i += plaintext.length;
          if (this.push(data)) {
            doImmediate(next);
          } else {
            if (nextWrite) {
              callback(new Error('illegal write'));
              return ;
            }
            nextWrite = next;
          }
        } else {
          callback();
        }
      };
      next();
    }
  });
}

// Decrypt received payload to the user
export function decryptStream (handshake: IHandshake, metrics?: MetricsRegistry, noiseMsgMaxLengthBytes?: number): streams.Duplex {
  const maxLengthBytes = noiseMsgMaxLengthBytes || -1;
  const maxLengthBytesWithoutTag = maxLengthBytes - 16;
  let nextWrite: Function | null = null;

  return new streams.Transform({
    autoDestroy: true,
    read(size: number) {
      const nextWriteLocal = nextWrite;
      if (nextWriteLocal) {
        nextWrite = null;
        nextWriteLocal();
      }
    },
    write(chunk: any, encoding: BufferEncoding, callback: (err?: any) => void): void {
      let i = 0;
      const next = () => {
        if (i < chunk.length) {
          let end = chunk.length;
          if (maxLengthBytes > 0) {
            end = i + maxLengthBytes;
            if (end > chunk.length) {
              end = chunk.length;
            }
          }

          if (end - TAG_LENGTH < i) {
            callback(new Error('Invalid chunk'));
            return;
          }

          const encrypted = chunk.subarray(i, end);
          // memory allocation is not cheap so reuse the encrypted Uint8Array
          // see https://github.com/ChainSafe/js-libp2p-noise/pull/242#issue-1422126164
          // this is ok because chacha20 reads bytes one by one and don't reread after that
          // it's also tested in https://github.com/ChainSafe/as-chacha20poly1305/pull/1/files#diff-25252846b58979dcaf4e41d47b3eadd7e4f335e7fb98da6c049b1f9cd011f381R48
          const dst = chunk.subarray(i, end - TAG_LENGTH);

          i += encrypted.length;

          const { plaintext: decrypted, valid } = handshake.decrypt(encrypted, handshake.session, dst);
          if (!valid) {
            metrics?.decryptErrors.increment();
            throw new Error('Failed to validate decrypted chunk');
          }
          metrics?.decryptedPackets.increment();
          if (this.push(decrypted)) {
            doImmediate(next);
          } else {
            if (nextWrite) {
              callback(new Error('illegal write'));
              return ;
            }
            nextWrite = next;
          }
        } else {
          callback();
        }
      };
      next();
    }
  });
}

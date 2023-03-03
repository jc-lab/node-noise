import type { bytes, bytes32 } from './@types/basic';
import type { CipherState, NoiseSession } from './@types/handshake';
import type { KeyPair } from './@types/keypair';
import type { IHandshake } from './@types/handshake-interface';
import type { ICryptoInterface } from './crypto';
import { InvalidCryptoExchangeError } from './errors';
import { decode0, decode1, decode2, encode0, encode1, encode2 } from './encoder';
import { XX } from './handshakes/xx';
import {
  logger,
  logLocalStaticKeys,
  logLocalEphemeralKeys,
  logRemoteEphemeralKey,
  logRemoteStaticKey,
  logCipherState
} from './logger';

import {HandshakeHandler} from './@types/handshake-interface';
import {PbStream} from './pb-stream';

export class XXHandshake implements IHandshake {
  public isInitiator: boolean
  public session: NoiseSession
  public handshakeHandler: HandshakeHandler | null;

  private remotePublicKey: bytes | null;

  protected payload: bytes
  protected connection: PbStream
  protected xx: XX
  protected staticKeypair: KeyPair

  private readonly prologue: bytes32

  constructor (
    isInitiator: boolean,
    payload: bytes,
    prologue: bytes32,
    crypto: ICryptoInterface,
    staticKeypair: KeyPair,
    connection: PbStream,
    handshakeHandler?: HandshakeHandler | null,
    remotePublicKey?: bytes | null,
    handshake?: XX | null
  ) {
    this.isInitiator = isInitiator;
    this.payload = payload;
    this.prologue = prologue;
    this.staticKeypair = staticKeypair;
    this.connection = connection;
    this.remotePublicKey = remotePublicKey || null;
    this.handshakeHandler = handshakeHandler || null;
    this.xx = handshake ?? new XX(crypto);
    this.session = this.xx.initSession(this.isInitiator, this.prologue, this.staticKeypair);
  }

  // stage 0
  public async propose (): Promise<void> {
    logLocalStaticKeys(this.session.hs.s);
    if (this.isInitiator) {
      logger('Stage 0 - Initiator starting to send first message.');
      const messageBuffer = this.xx.sendMessage(this.session, new Uint8Array(0));
      this.connection.writeLP(encode0(messageBuffer));
      logger('Stage 0 - Initiator finished sending first message.');
      logLocalEphemeralKeys(this.session.hs.e);
    } else {
      logger('Stage 0 - Responder waiting to receive first message...');
      const receivedMessageBuffer = decode0((await this.connection.readLP()).subarray());
      const { valid } = this.xx.recvMessage(this.session, receivedMessageBuffer);
      if (!valid) {
        throw new InvalidCryptoExchangeError('xx handshake stage 0 validation fail');
      }
      logger('Stage 0 - Responder received first message.');
      logRemoteEphemeralKey(this.session.hs.re);
    }
  }

  // stage 1
  public async exchange (): Promise<void> {
    if (this.isInitiator) {
      logger('Stage 1 - Initiator waiting to receive first message from responder...');
      const receivedMessageBuffer = decode1((await this.connection.readLP()).subarray());
      const { plaintext, valid } = this.xx.recvMessage(this.session, receivedMessageBuffer);
      if (!valid) {
        throw new InvalidCryptoExchangeError('xx handshake stage 1 validation fail');
      }
      logger('Stage 1 - Initiator received the message.');
      logRemoteEphemeralKey(this.session.hs.re);
      logRemoteStaticKey(this.session.hs.rs);

      logger('Initiator going to check remote\'s public key...');
      if (this.remotePublicKey && Buffer.compare(this.remotePublicKey, this.session.hs.rs) != 0) {
        throw new Error('not same remote public key');
      }

      return new Promise<void>((resolve, reject) => {
        if (this.handshakeHandler) {
          try {
            this.handshakeHandler(this.session, plaintext)
              .then((res) => {
                if (res) {
                  resolve();
                } else {
                  reject(new Error('Handshake rejected'));
                }
              })
              .catch((err) => {
                reject(new Error(`Handshake failed: ${err}`));
              });
          } catch (e) {
            reject(e);
          }
        } else {
          resolve();
        }
      });
    } else {
      logger('Stage 1 - Responder sending out first message with signed payload and static key.');
      const messageBuffer = this.xx.sendMessage(this.session, this.payload);
      this.connection.writeLP(encode1(messageBuffer));
      logger('Stage 1 - Responder sent the second handshake message with signed payload.');
      logLocalEphemeralKeys(this.session.hs.e);
    }
  }

  // stage 2
  public async finish (): Promise<void> {
    if (this.isInitiator) {
      logger('Stage 2 - Initiator sending third handshake message.');
      const messageBuffer = this.xx.sendMessage(this.session, this.payload);
      this.connection.writeLP(encode2(messageBuffer));
      logger('Stage 2 - Initiator sent message with signed payload.');
    } else {
      logger('Stage 2 - Responder waiting for third handshake message...');
      const receivedMessageBuffer = decode2((await this.connection.readLP()).subarray());
      const {plaintext, valid} = this.xx.recvMessage(this.session, receivedMessageBuffer);
      if (!valid) {
        throw new InvalidCryptoExchangeError('xx handshake stage 2 validation fail');
      }
      logger('Stage 2 - Responder received the message, finished handshake.');

      if (this.remotePublicKey && Buffer.compare(this.remotePublicKey, this.session.hs.rs) != 0) {
        throw new Error('not same remote public key');
      }

      return new Promise<void>((realResolve, reject) => {
        const resolve = () => {
          logCipherState(this.session);
          this.remotePublicKey = this.session.hs.rs;
          realResolve();
        };

        if (this.handshakeHandler) {
          try {
            this.handshakeHandler(this.session, plaintext)
              .then((res) => {
                if (res) {
                  resolve();
                } else {
                  reject(new Error('Handshake rejected'));
                }
              })
              .catch((err) => {
                reject(new Error(`Handshake failed: ${err}`));
              });
          } catch (e) {
            reject(e);
          }
        } else {
          resolve();
        }
      });
    }
  }

  public encrypt (plaintext: Uint8Array, session: NoiseSession): bytes {
    const cs = this.getCS(session);

    return this.xx.encryptWithAd(cs, new Uint8Array(0), plaintext);
  }

  public decrypt (ciphertext: Uint8Array, session: NoiseSession, dst?: Uint8Array): { plaintext: bytes, valid: boolean } {
    const cs = this.getCS(session, false);

    return this.xx.decryptWithAd(cs, new Uint8Array(0), ciphertext, dst);
  }

  public getRemoteStaticKey (): bytes {
    return this.remotePublicKey!!;
  }

  private getCS (session: NoiseSession, encryption = true): CipherState {
    if (!session.cs1 || !session.cs2) {
      throw new InvalidCryptoExchangeError('Handshake not completed properly, cipher state does not exist.');
    }

    if (this.isInitiator) {
      return encryption ? session.cs1 : session.cs2;
    } else {
      return encryption ? session.cs2 : session.cs1;
    }
  }
}

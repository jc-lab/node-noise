import type {HandshakeHandler, IHandshake} from './@types/handshake-interface';
import type {bytes, bytes32} from './@types/basic';
import {Action, CipherState, NoiseSession} from './@types/handshake';
import {PbStream} from './pb-stream';
import {KeyPair} from './@types/keypair';
import {ICryptoInterface} from './crypto';
import {InvalidCryptoExchangeError} from './errors';
import {PatternFlag, PatternHandshake} from './handshakes/pattern';
import {Metrics} from './@types/metrics';

export class Handshake implements IHandshake {
  public isInitiator: boolean
  public session: NoiseSession
  public handshakeHandler: HandshakeHandler | null;

  private remotePublicKey: bytes | null;

  protected payload: bytes
  protected connection: PbStream
  protected handshake: PatternHandshake
  protected staticKeypair: KeyPair

  private readonly prologue: bytes32

  private readonly metrics: Metrics | null

  constructor(
    isInitiator: boolean,
    payload: bytes,
    prologue: bytes32,
    crypto: ICryptoInterface,
    staticKeypair: KeyPair,
    connection: PbStream,
    handshake: PatternHandshake,
    handshakeHandler?: HandshakeHandler | null,
    remotePublicKey?: bytes | null,
    metrics?: Metrics | null
  ) {
    this.isInitiator = isInitiator;
    this.payload = payload;
    this.prologue = prologue;
    this.staticKeypair = staticKeypair;
    this.connection = connection;
    this.remotePublicKey = remotePublicKey || null;
    this.handshakeHandler = handshakeHandler || null;
    this.handshake = handshake;
    this.session = handshake.initSession(this.isInitiator, this.prologue, this.staticKeypair);
    this.metrics = metrics || null;
  }

  async doHandshake(): Promise<void> {
    if (this.handshake.pattern.flags & PatternFlag.FLAG_REMOTE_REQUIRED) {
      this.session.hs.rs = this.remotePublicKey;
    }

    while (true) {
      if (this.session.action === Action.READ_MESSAGE) {
        const data = await this.connection.readLP();
        const payload = this.handshake.readMessage(this.session, data);

        if (this.session.hs.rs) {
          if (this.remotePublicKey && Buffer.compare(this.remotePublicKey, this.session.hs.rs) != 0) {
            throw new Error('not same remote public key');
          }
          this.remotePublicKey = this.session.hs.rs;
        }

        if (this.handshakeHandler) {
          const res = await this.handshakeHandler(this.session, payload);
          if (!res) {
            throw new Error('handshake rejected');
          }
        }
      } else if (this.session.action === Action.WRITE_MESSAGE) {
        const messages = this.handshake.writeMessage(this.session, this.payload);
        this.connection.writeLP(messages.slice());
      } else if (this.session.action === Action.SPLIT) {
        const { cs1, cs2 } = this.handshake.split(this.session.hs.ss);

        this.session.cs1 = cs1;
        this.session.cs2 = cs2;

        return ;
      } else {
        throw new Error('illegal state');
      }
    }
  }

  decrypt(ciphertext: bytes, session: NoiseSession, dst?: Uint8Array | undefined): { plaintext: bytes; valid: boolean } {
    const cs = this.getCS(session, false);

    return this.handshake.decryptWithAd(cs, new Uint8Array(0), ciphertext, dst);
  }

  encrypt(plaintext: bytes, session: NoiseSession): bytes {
    const cs = this.getCS(session);

    return this.handshake.encryptWithAd(cs, new Uint8Array(0), plaintext);
  }

  getRemoteStaticKey(): bytes {
    return this.session.hs.rs!!;
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

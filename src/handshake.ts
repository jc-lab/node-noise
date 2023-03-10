import type {HandshakeHandler, IHandshake} from './@types/handshake-interface';
import type {bytes, bytes32} from './@types/basic';
import {Action, CipherState, NoiseSession} from './@types/handshake';
import {PbStream} from './pb-stream';
import {KeyPair} from './@types/keypair';
import {ICryptoInterface} from './crypto';
import {InvalidCryptoExchangeError} from './errors';
import {PatternFlag, PatternHandshake} from './handshakes/pattern';
import {Metrics} from './@types/metrics';

const EMPTY_BUFFER = new Uint8Array(0);

export class Handshake implements IHandshake {
  public isInitiator: boolean
  public session: NoiseSession
  public handshakeHandler: HandshakeHandler | null;

  private remotePublicKey: bytes | null;

  protected connection: PbStream
  protected handshake: PatternHandshake
  protected staticKeypair: KeyPair

  private readonly prologue: bytes32

  private readonly metrics: Metrics | null

  constructor(
    isInitiator: boolean,
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
    this.prologue = prologue;
    this.staticKeypair = staticKeypair;
    this.connection = connection;
    this.remotePublicKey = remotePublicKey || null;
    this.handshakeHandler = handshakeHandler || null;
    this.handshake = handshake;
    this.session = handshake.initSession(this.isInitiator, this.prologue, this.staticKeypair, remotePublicKey || null);
    this.metrics = metrics || null;
  }

  async doHandshake(): Promise<void> {
    const handshakeHandler = this.handshakeHandler;

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

        if (handshakeHandler && handshakeHandler.onReadMessage) {
          const res = await handshakeHandler.onReadMessage(this.session, payload);
          if (!res) {
            throw new Error('handshake rejected');
          }
        }
      } else if (this.session.action === Action.WRITE_MESSAGE) {
        let payload: Uint8Array = EMPTY_BUFFER;
        if (handshakeHandler && handshakeHandler.beforeWriteMessage) {
          const temp = await handshakeHandler.beforeWriteMessage(this.session);
          if (temp) {
            payload = temp;
          }
        }
        const messages = this.handshake.writeMessage(this.session, payload);
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

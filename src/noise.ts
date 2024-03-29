import * as streams from 'stream';
import duplexify from 'duplexify';
import type {bytes} from './@types/basic';
import type {IHandshake, HandshakeHandler} from './@types/handshake-interface';
import type {KeyPair} from './@types/keypair';
import type {ICryptoInterface} from './crypto';
import type {Metrics} from './@types/metrics';
import {stablelib} from './crypto/stablelib';
import {decryptStream, encryptStream} from './crypto/streaming';
import {MetricsRegistry, registerMetrics} from './metrics';
import {PbStream} from './pb-stream';
import {LengthPrefixedDecoder} from './length-prefixed-decoder';
import {PatternHandshake, PATTERNS} from './handshakes/pattern';
import {Handshake} from './handshake';


export interface HandshakeParams {
  connection: PbStream
  isInitiator: boolean
  remoteStaticPublicKey?: Uint8Array
  handshakeHandler?: HandshakeHandler
  noLengthCodec?: boolean;
  noiseMsgMaxLengthBytes?: number;
}

export interface SecuredConnection {
  conn: streams.Duplex
  remotePublicKey: Uint8Array
}


export interface NoiseInit {
  protocol?: string

  /**
   * x25519 private key, reuse for faster handshakes
   */
  staticNoiseKey?: bytes
  crypto?: ICryptoInterface
  prologueBytes?: Uint8Array
  metrics?: Metrics
}

interface NoiseProtocolSpec {
  pattern: string;
  dh: string;
  cipher: string;
  hash: string;
}

function parseSpec(name: string): NoiseProtocolSpec | null {
  const m = name.split('_');
  if (m.length != 5) {
    return null;
  }
  return {
    pattern: m[1],
    dh: m[2],
    cipher: m[3],
    hash: m[4]
  };
}

export class Noise {
  public readonly crypto: ICryptoInterface

  private readonly prologue: Uint8Array
  private readonly staticKeys: KeyPair
  private readonly metrics?: MetricsRegistry

  private readonly spec: NoiseProtocolSpec;
  private readonly handshake: PatternHandshake;

  constructor (init: NoiseInit = {}) {
    const name = init.protocol || 'Noise_XX_25519_ChaChaPoly_SHA256';
    const { staticNoiseKey, crypto, prologueBytes, metrics } = init;

    this.crypto = crypto ?? stablelib;
    this.metrics = metrics ? registerMetrics(metrics) : undefined;

    const spec = parseSpec(name);
    if (!spec) {
      throw new Error('invalid protocol name');
    }

    if (spec.dh !== '25519') {
      throw new Error(`not supported dh: ${spec.dh}`);
    }
    if (spec.cipher !== 'ChaChaPoly') {
      throw new Error(`not supported cipher: ${spec.cipher}`);
    }
    if (spec.hash !== 'SHA256') {
      throw new Error(`not supported hash: ${spec.hash}`);
    }

    const pattern = PATTERNS[spec.pattern];
    if (!pattern) {
      throw new Error(`not supported pattern: ${spec.pattern}`);
    }

    this.spec = spec;
    this.handshake = new PatternHandshake(this.crypto, name, pattern);

    if (staticNoiseKey) {
      // accepts x25519 private key of length 32
      this.staticKeys = this.crypto.generateX25519KeyPairFromSeed(staticNoiseKey);
    } else {
      this.staticKeys = this.crypto.generateX25519KeyPair();
    }
    this.prologue = prologueBytes ?? new Uint8Array(0);
  }

  public getPublicKey(): Uint8Array {
    return this.staticKeys.publicKey;
  }

  public async secureConnection(parameters: HandshakeParams): Promise<SecuredConnection> {
    const handshake = await this.performHandshake(parameters);
    const conn = await this.createSecureConnection(parameters.connection, handshake, parameters.noLengthCodec || false, parameters.noiseMsgMaxLengthBytes || -1);

    return {
      conn,
      remotePublicKey: handshake.getRemoteStaticKey()
    };
  }
  //
  // /**
  //  * Encrypt outgoing data to the remote party (handshake as initiator)
  //  *
  //  * @param {PeerId} localPeer - PeerId of the receiving peer
  //  * @param {Duplex<Uint8Array>} connection - streaming iterable duplex that will be encrypted
  //  * @param {PeerId} remotePeer - PeerId of the remote peer. Used to validate the integrity of the remote peer.
  //  * @returns {Promise<SecuredConnection>}
  //  */
  // public async secureOutbound (localPeer: PeerId, wrappedConnection: PbStream, remotePeer?: PeerId): Promise<SecuredConnection<NoiseExtensions>> {
  //   const handshake = await this.performHandshake({
  //     connection: wrappedConnection,
  //     isInitiator: true,
  //     localPeer,
  //     remotePeer
  //   })
  //   const conn = await this.createSecureConnection(wrappedConnection, handshake)
  //
  //   return {
  //     conn,
  //     remoteExtensions: handshake.remoteExtensions,
  //     remotePeer: handshake.remotePeer
  //   }
  // }
  //
  // /**
  //  * Decrypt incoming data (handshake as responder).
  //  *
  //  * @param {PeerId} localPeer - PeerId of the receiving peer.
  //  * @param {Duplex<Uint8Array>} connection - streaming iterable duplex that will be encryption.
  //  * @param {PeerId} remotePeer - optional PeerId of the initiating peer, if known. This may only exist during transport upgrades.
  //  * @returns {Promise<SecuredConnection>}
  //  */
  // public async secureInbound (localPeer: PeerId, wrappedConnection: PbStream, remotePeer?: PeerId): Promise<SecuredConnection<NoiseExtensions>> {
  //   const handshake = await this.performHandshake({
  //     connection: wrappedConnection,
  //     isInitiator: false,
  //     localPeer,
  //     remotePeer
  //   })
  //   const conn = await this.createSecureConnection(wrappedConnection, handshake)
  //
  //   return {
  //     conn,
  //     remotePeer: handshake.remotePeer,
  //     remoteExtensions: handshake.remoteExtensions
  //   }
  // }

  /**
   * If Noise pipes supported, tries IK handshake first with XX as fallback if it fails.
   * If noise pipes disabled or remote peer static key is unknown, use XX.
   *
   * @param {HandshakeParams} params
   */
  private async performHandshake (params: HandshakeParams): Promise<IHandshake> {
    const { isInitiator, remoteStaticPublicKey, connection, handshakeHandler } = params;
    const handshake = new Handshake(isInitiator, this.prologue, this.crypto, this.staticKeys, connection, this.handshake, handshakeHandler, remoteStaticPublicKey);

    try {
      await handshake.doHandshake();
      this.metrics?.handshakeSuccesses.increment();
    } catch (e) {
      this.metrics?.handshakeErrors.increment();
      if (e instanceof Error) {
        e.message = `Error occurred during ${this.spec.pattern} handshake: ${e.message}`;
      }
      throw e;
    }

    return handshake;
  }

  private createSecureConnection (
    connection: PbStream,
    handshake: IHandshake,
    noLengthCodec: boolean,
    noiseMsgMaxLengthBytes: number,
  ): streams.Duplex {
    // Create encryption box/unbox wrapper
    const network = connection.unwrap();

    const userOutbound = new streams.PassThrough();
    const userInbound = new streams.PassThrough();
    const userStream = new duplexify(userOutbound, userInbound);

    let s = userOutbound
      .pipe(encryptStream(handshake, this.metrics, noLengthCodec, noiseMsgMaxLengthBytes))
      .pipe(network);
    if (!noLengthCodec) {
      s = s.pipe(new LengthPrefixedDecoder());
    }
    s.pipe(decryptStream(handshake, this.metrics, noiseMsgMaxLengthBytes))
      .pipe(userInbound);

    return userStream;
  }
}

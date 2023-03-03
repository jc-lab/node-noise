import * as streams from 'stream';
import type { bytes } from './@types/basic';
import type { IHandshake } from './@types/handshake-interface';
import type { KeyPair } from './@types/keypair';
import type { ICryptoInterface } from './crypto';
import { stablelib } from './crypto/stablelib';
import { decryptStream, encryptStream } from './crypto/streaming';
import { XXHandshake } from './handshake-xx';
import type { Metrics } from './@types/metrics';
import { MetricsRegistry, registerMetrics } from './metrics';
import {PbStream} from './pb-stream';
import duplexify from 'duplexify';
import {LengthPrefixedDecoder} from './length-prefixed-decoder';
import {HandshakeHandler} from './@types/handshake-interface';

const EMPTY_BUFFER = new Uint8Array(0);

export interface HandshakeParams {
  connection: PbStream
  isInitiator: boolean
  remoteStaticPublicKey?: Uint8Array
  payload?: Uint8Array
  handshakeHandler?: HandshakeHandler
}

export interface SecuredConnection {
  conn: streams.Duplex
  remotePublicKey: Uint8Array
}


export interface NoiseInit {
  /**
   * x25519 private key, reuse for faster handshakes
   */
  staticNoiseKey?: bytes
  crypto?: ICryptoInterface
  prologueBytes?: Uint8Array
  metrics?: Metrics
}

export class Noise {
  public readonly crypto: ICryptoInterface

  private readonly prologue: Uint8Array
  private readonly staticKeys: KeyPair
  private readonly metrics?: MetricsRegistry

  constructor (init: NoiseInit = {}) {
    const { staticNoiseKey, crypto, prologueBytes, metrics } = init;

    this.crypto = crypto ?? stablelib;
    this.metrics = metrics ? registerMetrics(metrics) : undefined;

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
    const conn = await this.createSecureConnection(parameters.connection, handshake);

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
    return await this.performXXHandshake(params);
  }

  private async performXXHandshake (
    params: HandshakeParams
  ): Promise<XXHandshake> {
    const { isInitiator, remoteStaticPublicKey, connection, handshakeHandler } = params;
    const handshake = new XXHandshake(
      isInitiator,
      params.payload || EMPTY_BUFFER,
      this.prologue,
      this.crypto,
      this.staticKeys,
      connection,
      handshakeHandler,
      remoteStaticPublicKey
    );

    try {
      await handshake.propose();
      await handshake.exchange();
      await handshake.finish();
      this.metrics?.xxHandshakeSuccesses.increment();
    } catch (e: unknown) {
      this.metrics?.xxHandshakeErrors.increment();
      if (e instanceof Error) {
        e.message = `Error occurred during XX handshake: ${e.message}`;
        throw e;
      }
    }

    return handshake;
  }

  private createSecureConnection (
    connection: PbStream,
    handshake: IHandshake
  ): streams.Duplex {
    // Create encryption box/unbox wrapper
    const network = connection.unwrap();

    const userOutbound = new streams.PassThrough();
    const userInbound = new streams.PassThrough();
    const userStream = new duplexify(userOutbound, userInbound);

    userOutbound
      .pipe(encryptStream(handshake, this.metrics))
      .pipe(network)
      .pipe(new LengthPrefixedDecoder())
      .pipe(decryptStream(handshake, this.metrics))
      .pipe(userInbound);

    return userStream;
  }
}

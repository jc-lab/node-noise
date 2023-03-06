import {AbstractHandshake} from './abstract-handshake';
import {Action, HandshakeState, MessageBuffer, NoiseSession} from '../@types/handshake';
import {KeyPair} from '../@types/keypair';
import {bytes, bytes32} from '../@types/basic';
import {ICryptoInterface} from '../crypto';
import {Uint8ArrayList} from '../uint8arraylist';
import {InvalidCryptoExchangeError} from '../errors';

export enum PatternToken {
  // Token codes.
  S = 1,
  E = 2,
  EE = 3,
  ES = 4,
  SE = 5,
  SS = 6,
  F = 7,
  FF = 8,
  FLIP_DIR = 255,
}

export enum PatternFlag {
  FLAG_LOCAL_STATIC = 0x0001,
  FLAG_LOCAL_EPHEMERAL = 0x0002,
  FLAG_LOCAL_REQUIRED = 0x0004,
  FLAG_LOCAL_EPHEM_REQ = 0x0008,
  FLAG_LOCAL_HYBRID = 0x0010,
  FLAG_LOCAL_HYBRID_REQ = 0x0020,
  FLAG_REMOTE_STATIC = 0x0100,
  FLAG_REMOTE_EPHEMERAL = 0x0200,
  FLAG_REMOTE_REQUIRED = 0x0400,
  FLAG_REMOTE_EPHEM_REQ = 0x0800,
  FLAG_REMOTE_HYBRID = 0x1000,
  FLAG_REMOTE_HYBRID_REQ = 0x2000,
}

enum Requirement {
  LOCAL_REQUIRED = 0x01,
  REMOTE_REQUIRED = 0x02,
  PSK_REQUIRED = 0x04,
  FALLBACK_PREMSG = 0x08,
  LOCAL_PREMSG = 0x10,
  REMOTE_PREMSG = 0x20,
  FALLBACK_POSSIBLE = 0x40,
}

export interface Pattern {
  flags: PatternFlag;
  steps: PatternToken[];
}

export const PATTERNS: Readonly<Record<string, Pattern>> = Object.freeze({
  'N': {
    flags:
      PatternFlag.FLAG_LOCAL_EPHEMERAL |
      PatternFlag.FLAG_REMOTE_STATIC |
      PatternFlag.FLAG_REMOTE_REQUIRED,
    steps: [
      PatternToken.E,
      PatternToken.ES
    ]
  },
  // 'X': {
  //   flags:
  //     PatternFlag.FLAG_LOCAL_STATIC |
  //     PatternFlag.FLAG_LOCAL_EPHEMERAL |
  //     PatternFlag.FLAG_REMOTE_STATIC |
  //     PatternFlag.FLAG_REMOTE_REQUIRED,
  //   steps: [
  //     PatternToken.E,
  //     PatternToken.ES,
  //     PatternToken.S,
  //     PatternToken.SS
  //   ]
  // },
  'NN': {
    flags:
      PatternFlag.FLAG_LOCAL_EPHEMERAL |
      PatternFlag.FLAG_REMOTE_EPHEMERAL,
    steps: [
      PatternToken.E,
      PatternToken.FLIP_DIR,
      PatternToken.E,
      PatternToken.EE
    ]
  },
  'NK': {
    flags:
      PatternFlag.FLAG_LOCAL_EPHEMERAL |
      PatternFlag.FLAG_REMOTE_STATIC |
      PatternFlag.FLAG_REMOTE_EPHEMERAL |
      PatternFlag.FLAG_REMOTE_REQUIRED,
    steps: [
      PatternToken.E,
      PatternToken.ES,
      PatternToken.FLIP_DIR,
      PatternToken.E,
      PatternToken.EE
    ]
  },
  'NX': {
    flags:
      PatternFlag.FLAG_LOCAL_EPHEMERAL |
      PatternFlag.FLAG_REMOTE_STATIC |
      PatternFlag.FLAG_REMOTE_EPHEMERAL,
    steps: [
      PatternToken.E,
      PatternToken.FLIP_DIR,
      PatternToken.E,
      PatternToken.EE,
      PatternToken.S,
      PatternToken.ES
    ]
  },
  'XN': {
    flags:
      PatternFlag.FLAG_LOCAL_STATIC |
      PatternFlag.FLAG_LOCAL_EPHEMERAL |
      PatternFlag.FLAG_REMOTE_EPHEMERAL,
    steps: [
      PatternToken.E,
      PatternToken.FLIP_DIR,
      PatternToken.E,
      PatternToken.EE,
      PatternToken.FLIP_DIR,
      PatternToken.S,
      PatternToken.SE
    ]
  },
  'XK': {
    flags:
      PatternFlag.FLAG_LOCAL_STATIC |
      PatternFlag.FLAG_LOCAL_EPHEMERAL |
      PatternFlag.FLAG_REMOTE_STATIC |
      PatternFlag.FLAG_REMOTE_EPHEMERAL |
      PatternFlag.FLAG_REMOTE_REQUIRED,
    steps: [
      PatternToken.E,
      PatternToken.ES,
      PatternToken.FLIP_DIR,
      PatternToken.E,
      PatternToken.EE,
      PatternToken.FLIP_DIR,
      PatternToken.S,
      PatternToken.SE
    ]
  },
  'XX': {
    flags:
      PatternFlag.FLAG_LOCAL_STATIC |
      PatternFlag.FLAG_LOCAL_EPHEMERAL |
      PatternFlag.FLAG_REMOTE_STATIC |
      PatternFlag.FLAG_REMOTE_EPHEMERAL,
    steps: [
      PatternToken.E,
      PatternToken.FLIP_DIR,
      PatternToken.E,
      PatternToken.EE,
      PatternToken.S,
      PatternToken.ES,
      PatternToken.FLIP_DIR,
      PatternToken.S,
      PatternToken.SE
    ]
  }
  // 'KN': {
  //   flags:
  //     PatternFlag.FLAG_LOCAL_STATIC |
  //     PatternFlag.FLAG_LOCAL_EPHEMERAL |
  //     PatternFlag.FLAG_LOCAL_REQUIRED |
  //     PatternFlag.FLAG_REMOTE_EPHEMERAL,
  //   steps: [
  //     PatternToken.E,
  //     PatternToken.FLIP_DIR,
  //     PatternToken.E,
  //     PatternToken.EE,
  //     PatternToken.SE
  //   ]
  // },
  // 'KK': {
  //   flags:
  //     PatternFlag.FLAG_LOCAL_STATIC |
  //     PatternFlag.FLAG_LOCAL_EPHEMERAL |
  //     PatternFlag.FLAG_LOCAL_REQUIRED |
  //     PatternFlag.FLAG_REMOTE_STATIC |
  //     PatternFlag.FLAG_REMOTE_EPHEMERAL |
  //     PatternFlag.FLAG_REMOTE_REQUIRED,
  //   steps: [
  //     PatternToken.E,
  //     PatternToken.ES,
  //     PatternToken.SS,
  //     PatternToken.FLIP_DIR,
  //     PatternToken.E,
  //     PatternToken.EE,
  //     PatternToken.SE
  //   ]
  // }
});

function reverseFlags(flags: number): number {
  return (((flags >> 8) & 0x00FF) | ((flags << 8) & 0xFF00)) & 0xffff;
}

function computeRequirements(flags: number, isFallback: boolean): Requirement {
  let requirements = 0;

  if ((flags & PatternFlag.FLAG_LOCAL_STATIC) != 0) {
    requirements |= Requirement.LOCAL_REQUIRED;
  }
  if ((flags & PatternFlag.FLAG_LOCAL_REQUIRED) != 0) {
    requirements |= Requirement.LOCAL_REQUIRED;
    requirements |= Requirement.LOCAL_PREMSG;
  }
  if ((flags & PatternFlag.FLAG_REMOTE_REQUIRED) != 0) {
    requirements |= Requirement.REMOTE_REQUIRED;
    requirements |= Requirement.REMOTE_PREMSG;
  }
  if ((flags & (PatternFlag.FLAG_REMOTE_EPHEM_REQ | PatternFlag.FLAG_LOCAL_EPHEM_REQ)) != 0) {
    if (isFallback)
      requirements |= Requirement.FALLBACK_PREMSG;
  }
  // if (prefix.equals("NoisePSK")) {
  //   requirements |= Requirement.PSK_REQUIRED;
  // }
  return requirements;
}

export class PatternHandshake extends AbstractHandshake {
  constructor(crypto: ICryptoInterface, public readonly name: string, public readonly pattern: Pattern) {
    super(crypto);
  }

  initSession(initiator: boolean, prologue: bytes32, s: KeyPair, remotePublicKey: bytes | null): NoiseSession {
    const ss = this.initializeSymmetric(this.name);
    this.mixHash(ss, prologue);

    const hs: HandshakeState = { ss, s, rs: null, psk: null, re: null, e: null };

    const flags = initiator ? this.pattern.flags : reverseFlags(this.pattern.flags);
    const requirements = computeRequirements(flags, false);

    // const psk: Uint8Array | null = null;
    // if (psk && psk.length > 0) {
    //   // mixPreSharedKey
    // }

    if (this.pattern.flags & PatternFlag.FLAG_REMOTE_REQUIRED) {
      hs.rs = remotePublicKey;
    }

    if (initiator) {
      if ((requirements & Requirement.LOCAL_PREMSG) != 0) {
        this.mixHash(ss, s.publicKey);
      }
      // if ((requirements & Requirement.FALLBACK_PREMSG) != 0) {
      //   this.mixHash(ss, remoteEphemeral);
      //   if (remoteHybrid != null)
      //     this.mixHash(ss, remoteHybrid);
      //   if (preSharedKey != null)
      //     symmetric.mixPublicKeyIntoCK(remoteEphemeral);
      // }
      if ((requirements & Requirement.REMOTE_PREMSG) != 0) {
        this.mixHash(ss, hs.rs!);
      }
    } else {
      if ((requirements & Requirement.REMOTE_PREMSG) != 0) {
        this.mixHash(ss, hs.rs!);
      }
      // if ((requirements & Requirement.FALLBACK_PREMSG) != 0) {
      //   this.mixHash(ss, localEphemeral);
      //   if (localHybrid != null)
      //     this.mixHash(ss, localHybrid);
      //   if (preSharedKey != null)
      //     symmetric.mixPublicKeyIntoCK(localEphemeral);
      // }
      if ((requirements & Requirement.LOCAL_PREMSG) != 0) {
        this.mixHash(ss, s.publicKey);
      }
    }

    return {
      hs,
      i: initiator,
      mc: 0,
      action: initiator ? Action.WRITE_MESSAGE : Action.READ_MESSAGE,
      patternIndex: 0
    };
  }

  public writeMessage (session: NoiseSession, message: bytes): Uint8ArrayList {
    const buffer = new Uint8ArrayList();

    if (session.action != Action.WRITE_MESSAGE) {
      throw new Error('invalid state');
    }

    while (true) {
      if (session.patternIndex >= this.pattern.steps.length) {
        session.action = Action.SPLIT;
        break;
      }

      const token = this.pattern.steps[session.patternIndex++];
      if (token === PatternToken.FLIP_DIR) {
        session.action = Action.READ_MESSAGE;
        break;
      }

      switch (token) {
        case PatternToken.E:
          session.hs.e = this.crypto.generateX25519KeyPair();
          this.mixHash(session.hs.ss, session.hs.e.publicKey);
          buffer.append(session.hs.e.publicKey);

          // If the protocol is using pre-shared keys, then also mix
          // the local ephemeral key into the chaining key.
          if (session.hs.psk && session.hs.psk.length > 0) {
            this.mixKey(session.hs.ss, session.hs.e.publicKey);
          }

          break;

        case PatternToken.S:
          buffer.append(this.encryptAndHash(session.hs.ss, session.hs.s.publicKey));
          break;

        case PatternToken.EE:
          this.mixKey(session.hs.ss, this.dh(session.hs.e!.privateKey, session.hs.re!));
          break;

        case PatternToken.ES:
          if (session.i) {
            this.mixKey(session.hs.ss, this.dh(session.hs.e!.privateKey, session.hs.rs!));
          } else {
            this.mixKey(session.hs.ss, this.dh(session.hs.s!.privateKey, session.hs.re!));
          }
          break;

        case PatternToken.SE:
          if (session.i) {
            this.mixKey(session.hs.ss, this.dh(session.hs.s!.privateKey, session.hs.re!));
          } else {
            this.mixKey(session.hs.ss, this.dh(session.hs.e!.privateKey, session.hs.rs!));
          }
          break;

        case PatternToken.SS:
          this.mixKey(session.hs.ss, this.dh(session.hs.e!.privateKey, session.hs.rs!));
          break;

        default:
          throw new Error(`not supported token: ${token}`);
      }
    }

    buffer.append(this.encryptAndHash(session.hs.ss, message));

    if (session.action === Action.SPLIT) {
      const { cs1, cs2 } = this.split(session.hs.ss);
      session.cs1 = cs1;
      session.cs2 = cs2;
    }

    return buffer;
  }

  public readMessage (session: NoiseSession, message: Uint8Array): bytes {
    if (session.action != Action.READ_MESSAGE) {
      throw new Error('invalid state');
    }

    const publicKeySize = session.hs.s.publicKey.length;
    const macSize = 16;
    let messagePos = 0;

    while (true) {
      if (session.patternIndex >= this.pattern.steps.length) {
        session.action = Action.SPLIT;
        break;
      }

      const token = this.pattern.steps[session.patternIndex++];
      if (token === PatternToken.FLIP_DIR) {
        session.action = Action.WRITE_MESSAGE;
        break;
      }

      const space = message.length - messagePos;
      let size: number;

      switch (token) {
        case PatternToken.E:
          if (space < publicKeySize) {
            throw new Error('short buffer');
          }
          session.hs.re = message.slice(messagePos, messagePos + publicKeySize);
          messagePos += publicKeySize;

          this.mixHash(session.hs.ss, session.hs.re);

          // If the protocol is using pre-shared keys, then also mix
          // the local ephemeral key into the chaining key.
          if (session.hs.psk && session.hs.psk.length > 0) {
            this.mixKey(session.hs.ss, session.hs.re);
          }

          break;

        case PatternToken.S:
          size = publicKeySize + macSize;
          if (space < size) {
            throw new Error('short buffer');
          }

          const decrypted = this.decryptAndHash(session.hs.ss, message.slice(messagePos, messagePos + size));
          if (!decrypted.valid) {
            throw new InvalidCryptoExchangeError('handshake validation fail');
          }

          session.hs.rs = decrypted.plaintext;
          messagePos += size;

          break;

        case PatternToken.EE:
          this.mixKey(session.hs.ss, this.dh(session.hs.e!.privateKey, session.hs.re!));
          break;

        case PatternToken.ES:
          if (session.i) {
            this.mixKey(session.hs.ss, this.dh(session.hs.e!.privateKey, session.hs.rs!));
          } else {
            this.mixKey(session.hs.ss, this.dh(session.hs.s!.privateKey, session.hs.re!));
          }
          break;

        case PatternToken.SE:
          if (session.i) {
            this.mixKey(session.hs.ss, this.dh(session.hs.s!.privateKey, session.hs.re!));
          } else {
            this.mixKey(session.hs.ss, this.dh(session.hs.e!.privateKey, session.hs.rs!));
          }
          break;

        case PatternToken.SS:
          this.mixKey(session.hs.ss, this.dh(session.hs.e!.privateKey, session.hs.rs!));
          break;

        default:
          throw new Error(`not supported token: ${token}`);
      }
    }

    const ciphertext = message.slice(messagePos);
    const decrypted = this.decryptAndHash(session.hs.ss, ciphertext);
    if (!decrypted.valid) {
      throw new InvalidCryptoExchangeError('handshake validation fail');
    }

    return decrypted.plaintext;
  }
}

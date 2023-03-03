import {stablelib} from './crypto/stablelib';
import {XXHandshake} from './handshake-xx';
import {createPbStream} from './pb-stream';

describe('XX Handshake', () => {
  const fakeStaticKey = stablelib.generateX25519KeyPair();

  // it('should propose, exchange and finish handshake', async () => {
  //   try {
  //     const connectionFrom = createPbStream();
  //     const connectionTo = createPbStream();
  //     connectionFrom.pipe(connectionTo).pipe(connectionFrom);
  //
  //     const prologue = Buffer.alloc(0);
  //     const staticKeysInitiator = stablelib.generateX25519KeyPair();
  //     const staticKeysResponder = stablelib.generateX25519KeyPair();
  //
  //     const initPayload = Buffer.from('aaaa', 'ascii');
  //     const handshakeInitator = new XXHandshake(true, initPayload, prologue, stablelib, staticKeysInitiator, connectionFrom, null, staticKeysResponder.publicKey);
  //
  //     const respPayload = Buffer.from('bbbb', 'ascii');
  //     const handshakeResponder = new XXHandshake(false, respPayload, prologue, stablelib, staticKeysResponder, connectionTo, null, staticKeysInitiator.publicKey);
  //
  //     await handshakeInitator.propose();
  //     await handshakeResponder.propose();
  //
  //     await handshakeResponder.exchange();
  //     await handshakeInitator.exchange();
  //
  //     await handshakeInitator.finish();
  //     await handshakeResponder.finish();
  //
  //     const sessionInitator = handshakeInitator.session;
  //     const sessionResponder = handshakeResponder.session;
  //
  //     // Test shared key
  //     if (sessionInitator.cs1 && sessionResponder.cs1 && sessionInitator.cs2 && sessionResponder.cs2) {
  //       expect(Buffer.compare(sessionInitator.cs1.k, sessionResponder.cs1.k) == 0).toBeTruthy();
  //       expect(Buffer.compare(sessionInitator.cs2.k, sessionResponder.cs2.k) == 0).toBeTruthy();
  //     } else {
  //       expect(false).toBeTruthy();
  //     }
  //
  //     // Test encryption and decryption
  //     const encrypted = handshakeInitator.encrypt(Buffer.from('encryptthis'), handshakeInitator.session);
  //     const {plaintext: decrypted, valid} = handshakeResponder.decrypt(encrypted, handshakeResponder.session);
  //     expect(Buffer.compare(decrypted, Buffer.from('encryptthis')) == 0).toBeTruthy();
  //     expect(valid).toBeTruthy();
  //   } catch (e) {
  //     const err = e as Error;
  //     expect(false, err.message).toBeTruthy();
  //   }
  // });
  //
  // it('Initiator should fail to exchange handshake if given wrong public key in payload', async () => {
  //   try {
  //     const connectionFrom = createPbStream();
  //     const connectionTo = createPbStream();
  //     connectionFrom.pipe(connectionTo).pipe(connectionFrom);
  //
  //     const prologue = Buffer.alloc(0);
  //     const staticKeysInitiator = stablelib.generateX25519KeyPair();
  //     const staticKeysResponder = stablelib.generateX25519KeyPair();
  //
  //     const initPayload = Buffer.from('aaaa', 'ascii');
  //     const handshakeInitator = new XXHandshake(true, initPayload, prologue, stablelib, staticKeysInitiator, connectionFrom, null, fakeStaticKey.publicKey);
  //
  //     const respPayload = Buffer.from('bbbb', 'ascii');
  //     const handshakeResponder = new XXHandshake(false, respPayload, prologue, stablelib, staticKeysResponder, connectionTo, null, staticKeysInitiator.publicKey);
  //
  //     await handshakeInitator.propose();
  //     await handshakeResponder.propose();
  //
  //     await handshakeResponder.exchange();
  //     await handshakeInitator.exchange();
  //
  //     console.error('asdasdasdsdasdasdasdsdasdasdasdsdasdasdasdsdasdasdasdsdasdasdasdsdasdasdasdsdasdasdasdsdvv');
  //
  //     expect(false, 'Should throw exception').toBeTruthy();
  //   } catch (e) {
  //     const err = e as Error;
  //     expect(err.message).toEqual('not same remote public key');
  //     // expect(err.message).equals(`Error occurred while verifying signed payload: Payload identity key ${peerB.toString()} does not match expected remote peer ${fakePeer.toString()}`)
  //   }
  // });

  it('Responder should fail to exchange handshake if given wrong public key in payload', async () => {
    try {
      const connectionFrom = createPbStream();
      const connectionTo = createPbStream();
      connectionFrom.pipe(connectionTo).pipe(connectionFrom);

      const prologue = Buffer.alloc(0);
      const staticKeysInitiator = stablelib.generateX25519KeyPair();
      const staticKeysResponder = stablelib.generateX25519KeyPair();

      const initPayload = Buffer.from('aaaa', 'ascii');
      const handshakeInitator = new XXHandshake(true, initPayload, prologue, stablelib, staticKeysInitiator, connectionFrom, null, staticKeysResponder.publicKey);

      const respPayload = Buffer.from('bbbb', 'ascii');
      const handshakeResponder = new XXHandshake(false, respPayload, prologue, stablelib, staticKeysResponder, connectionTo, null, fakeStaticKey.publicKey);

      await handshakeInitator.propose();
      await handshakeResponder.propose();

      await handshakeResponder.exchange();
      await handshakeInitator.exchange();

      await handshakeInitator.finish();
      await handshakeResponder.finish();

      expect(false, 'Should throw exception').toBeTruthy();
    } catch (e) {
      const err = e as Error;
      expect(err.message).toEqual('not same remote public key');
      // expect(err.message).equals(`Error occurred while verifying signed payload: Payload identity key ${peerA.toString()} does not match expected remote peer ${fakePeer.toString()}`)
    }
  });
});

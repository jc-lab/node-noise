import type { KeyPair } from '../@types/keypair';
import type { NoiseSession } from '../@types/handshake';
import { stablelib } from '../crypto/stablelib';
import { XX } from './xx';

function uint8ArrayToString(a: Uint8Array, encoding: BufferEncoding): string {
  return Buffer.from(a).toString(encoding);
}

describe('XX Handshake', () => {
  const prologue = Buffer.alloc(0);

  it('Test creating new XX session', async () => {
    try {
      const xx = new XX(stablelib);

      const kpInitiator: KeyPair = stablelib.generateX25519KeyPair();

      await xx.initSession(true, prologue, kpInitiator);
    } catch (e) {
      const err = e as Error;
      expect(false, err.message).toBeTruthy();
    }
  });

  it('Test get HKDF', () => {
    const ckBytes = Buffer.from('4e6f6973655f58585f32353531395f58436861436861506f6c795f53484132353600000000000000000000000000000000000000000000000000000000000000', 'hex');
    const ikm = Buffer.from('a3eae50ea37a47e8a7aa0c7cd8e16528670536dcd538cebfd724fb68ce44f1910ad898860666227d4e8dd50d22a9a64d1c0a6f47ace092510161e9e442953da3', 'hex');
    const ck = Buffer.alloc(32);
    ckBytes.copy(ck);

    const [k1, k2, k3] = stablelib.getHKDF(ck, ikm);
    expect(uint8ArrayToString(k1, 'hex')).toEqual('cc5659adff12714982f806e2477a8d5ddd071def4c29bb38777b7e37046f6914');
    expect(uint8ArrayToString(k2, 'hex')).toEqual('a16ada915e551ab623f38be674bb4ef15d428ae9d80688899c9ef9b62ef208fa');
    expect(uint8ArrayToString(k3, 'hex')).toEqual('ff67bf9727e31b06efc203907e6786667d2c7a74ac412b4d31a80ba3fd766f68');
  });

  async function doHandshake (xx: XX): Promise<{ nsInit: NoiseSession, nsResp: NoiseSession }> {
    const kpInit = stablelib.generateX25519KeyPair();
    const kpResp = stablelib.generateX25519KeyPair();

    // initiator: new XX noise session
    const nsInit = xx.initSession(true, prologue, kpInit);
    // responder: new XX noise session
    const nsResp = xx.initSession(false, prologue, kpResp);

    /* STAGE 0 */

    // initiator sends message
    const message = Buffer.from('HELLO', 'ascii');
    const messageBuffer = xx.sendMessage(nsInit, message);

    expect(messageBuffer.ne.length).not.toEqual(0);

    // responder receives message
    xx.recvMessage(nsResp, messageBuffer);

    /* STAGE 1 */

    // responder creates payload
    const message1 = Buffer.from('WORLD', 'ascii');
    const messageBuffer2 = xx.sendMessage(nsResp, message1);

    expect(messageBuffer2.ne.length).not.toEqual(0);
    expect(messageBuffer2.ns.length).not.toEqual(0);

    // initiator receive payload
    xx.recvMessage(nsInit, messageBuffer2);

    /* STAGE 2 */

    // initiator send message
    const messageBuffer3 = xx.sendMessage(nsInit, Buffer.alloc(0));

    // responder receive message
    xx.recvMessage(nsResp, messageBuffer3);

    if (nsInit.cs1 == null || nsResp.cs1 == null || nsInit.cs2 == null || nsResp.cs2 == null) {
      throw new Error('CipherState missing');
    }

    expect(Buffer.compare(nsInit.cs1.k, nsResp.cs1.k) === 0).toBeTruthy();
    expect(Buffer.compare(nsInit.cs2.k, nsResp.cs2.k) === 0).toBeTruthy();

    return { nsInit, nsResp };
  }

  it('Test handshake', async () => {
    try {
      const xx = new XX(stablelib);
      await doHandshake(xx);
    } catch (e) {
      const err = e as Error;
      expect(false, err.message).toBeTruthy();
    }
  });

  it('Test symmetric encrypt and decrypt', async () => {
    try {
      const xx = new XX(stablelib);
      const { nsInit, nsResp } = await doHandshake(xx);
      const ad = Buffer.from('authenticated');
      const message = Buffer.from('HelloCrypto');

      if (nsInit.cs1 == null || nsResp.cs1 == null || nsInit.cs2 == null || nsResp.cs2 == null) {
        throw new Error('CipherState missing');
      }

      const ciphertext = xx.encryptWithAd(nsInit.cs1, ad, message);
      expect(Buffer.compare(Buffer.from('HelloCrypto'), ciphertext) == 0, 'Encrypted message should not be same as plaintext.').not.toBeTruthy();
      const { plaintext: decrypted, valid } = xx.decryptWithAd(nsResp.cs1, ad, ciphertext);

      expect(Buffer.compare(Buffer.from('HelloCrypto'), decrypted) == 0, 'Decrypted text equal to original message.').toBeTruthy();
      expect(valid).toBeTruthy();
    } catch (e) {
      const err = e as Error;
      expect(false, err.message).toBeTruthy();
    }
  });

  it('Test multiple messages encryption and decryption', async () => {
    const xx = new XX(stablelib);
    const { nsInit, nsResp } = await doHandshake(xx);
    const ad = Buffer.from('authenticated');
    const message = Buffer.from('ethereum1');

    if (nsInit.cs1 == null || nsResp.cs1 == null || nsInit.cs2 == null || nsResp.cs2 == null) {
      throw new Error('CipherState missing');
    }

    const encrypted = xx.encryptWithAd(nsInit.cs1, ad, message);
    const { plaintext: decrypted } = xx.decryptWithAd(nsResp.cs1, ad, encrypted);
    expect('ethereum1', 'Decrypted text not equal to original message.').toEqual(uint8ArrayToString(decrypted, 'utf8'));

    const message2 = Buffer.from('ethereum2');
    const encrypted2 = xx.encryptWithAd(nsInit.cs1, ad, message2);
    const { plaintext: decrypted2 } = xx.decryptWithAd(nsResp.cs1, ad, encrypted2);
    expect('ethereum2', 'Decrypted text not equal to original message.').toEqual(uint8ArrayToString(decrypted2, 'utf-8'));
  });
});

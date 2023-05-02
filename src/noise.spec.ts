import {Noise, createPbStream} from './';
import * as streams from 'stream';

export class EchoStream extends streams.Duplex {
  constructor() {
    super({
      autoDestroy: true
    });
  }

  _read() {
  }

  _write(chunk: any, encoding: BufferEncoding, callback: (error?: (Error | null)) => void) {
    setTimeout(() => {
      this.push(chunk);
      callback();
    }, 100);
  }
}

async function setupConnection() {
  const noiseA = new Noise();
  const noiseB = new Noise();

  const streamA = createPbStream();
  const streamB = createPbStream();

  streamA
    .pipe(streamB)
    .pipe(streamA);

  const connAPromise = noiseA.secureConnection({
    connection: streamA,
    isInitiator: false,
    remoteStaticPublicKey: noiseB.getPublicKey(),
    noLengthCodec: true
  });

  const connBPromise = noiseB.secureConnection({
    connection: streamB,
    isInitiator: true,
    remoteStaticPublicKey: noiseA.getPublicKey(),
    noLengthCodec: true
  });

  const connA = await connAPromise;
  const connB = await connBPromise;

  connA.conn.pipe(new EchoStream()).pipe(connA.conn);

  return {
    noiseA, noiseB, streamA, streamB, connA, connB
  };
}

describe('secure connection', () => {
  it('payload 4kb',  async () => {
    const { noiseA, noiseB, streamA, streamB, connA, connB } = await setupConnection();

    const payload = Buffer.from('A'.repeat(4096));

    const received = await new Promise<Buffer>((resolve, reject) => {
      const timer = setTimeout(() => {
        connB.conn.off('data', handler);
        reject(new Error('timeout'));
      }, 1000);
      const handler = (chunk: any) => {
        clearTimeout(timer);
        resolve(chunk);
      };
      connB.conn.on('data', handler);
      connB.conn.write(payload);
    });

    expect(received.toString('hex')).toEqual(payload.toString('hex'));
  });

  it('payload 128kb',  async () => {
    const { noiseA, noiseB, streamA, streamB, connA, connB } = await setupConnection();

    const payload = Buffer.from('A'.repeat(128 * 1024));

    const received = await new Promise<Buffer>((resolve, reject) => {
      const timer = setTimeout(() => {
        connB.conn.off('data', handler);
        reject(new Error('timeout'));
      }, 1000);
      const handler = (chunk: any) => {
        clearTimeout(timer);
        resolve(chunk);
      };
      connB.conn.on('data', handler);
      connB.conn.write(payload);
    });

    expect(received.toString('hex')).toEqual(payload.toString('hex'));
  });
});

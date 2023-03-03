import * as streams from 'stream';
import { Uint8ArrayList } from './uint8arraylist';
import { uint16BEEncode, uint16BEDecode } from './encoder';
import {NOISE_MSG_MAX_LENGTH_BYTES} from './constants';
import duplexify from 'duplexify';

interface RingItem<D> {
  next: RingItem<D> | null;
  data: D;
}

interface PendingReader {
  resolve: (d: Uint8Array) => void;
  reject: (err: any) => void;
}

class RingBuffer {
  private buffers: Uint8Array[] = [];
  private pendingReaders: PendingReader[] = [];

  public push(data: Uint8Array) {
    const pendingReader = this.pendingReaders.shift();
    if (pendingReader) {
      pendingReader.resolve(data);
    } else {
      this.buffers.push(data);
    }
  }

  public poll(): Promise<Uint8Array> {
    return new Promise<Uint8Array>((resolve, reject) => {
      const buffered = this.buffers.shift();
      if (buffered) {
        resolve(buffered);
      } else {
        this.pendingReaders.push({
          resolve, reject
        });
      }
    });
  }

  public pop(): Uint8Array | undefined {
    return this.buffers.shift();
  }

  public close(err: any) {
    let item: PendingReader | undefined;
    while (!!(item = this.pendingReaders.shift())) {
      item.reject(err);
    }
  }
}

export interface PbStream {
  writeLP(input: Uint8Array): void;
  readLP(): Promise<Uint8Array>;
  unwrap(): streams.Duplex;
}

type CallbackType = (error?: (Error | null)) => void;

export class PbStreamImpl extends streams.Duplex implements PbStream {
  private readonly ringBuffer = new RingBuffer();
  private readonly receiveBuffer = new Uint8ArrayList();
  private readonly maxLength: number;
  private unwrapped: duplexify.Duplexify | null = null;
  private unwrappedOutbound: streams.Writable | null = null;
  private unwrappedInbound: streams.PassThrough | null = null;

  private nextWrite: CallbackType | null = null;

  constructor(options?: streams.DuplexOptions & { maxLength?: number }) {
    super({
      autoDestroy: true,
      ...options
    });

    this.maxLength = options?.maxLength || NOISE_MSG_MAX_LENGTH_BYTES;
  }

  writeLP(input: Uint8Array): void {
    this.push(uint16BEEncode(input.length));
    this.push(input);
  }

  readLP(): Promise<Uint8Array> {
    return this.ringBuffer.poll();
  }

  unwrap(): streams.Duplex {
    const self = this;
    if (this.unwrapped) {
      return this.unwrapped;
    }

    this.unwrappedOutbound = new streams.Writable({
      autoDestroy: true,
      write(chunk: any, encoding: BufferEncoding, callback: (error?: (Error | null)) => void) {
        const ret = self.push(chunk);
        if (ret) {
          callback();
        } else {
          if (self.nextWrite) {
            callback(new Error('Writing'));
          } else {
            self.nextWrite = callback;
          }
        }
        return ;
      }
    });
    this.unwrappedInbound = new streams.PassThrough();
    this.unwrapped = new duplexify(this.unwrappedOutbound, this.unwrappedInbound);

    const next = (err?: any) => {
      if (err) {
        return ;
      }

      const item = this.ringBuffer.pop();
      if (item) {
        this.unwrappedInbound!!.write(item, next);
      } else {
        const bufferedLength = this.receiveBuffer.length;
        if (bufferedLength > 0) {
          this.unwrappedInbound!!.write(this.receiveBuffer.slice(0, bufferedLength));
          this.receiveBuffer.consume(bufferedLength);
        }
      }
    };
    next();


    return this.unwrapped;
  }

  _read(size: number) {
    const nextWrite = this.nextWrite;
    this.nextWrite = null;
    if (nextWrite) {
      nextWrite();
    }
  }

  _write(chunk: any, encoding: BufferEncoding, callback: (error?: (Error | null)) => void) {
    if (this.unwrapped) {
      this.unwrappedInbound!!.write(chunk, encoding, callback);
      return ;
    }

    this.receiveBuffer.append(chunk);

    const next = (): void => {
      if (this.receiveBuffer.length >= 2) {
        const length = uint16BEDecode(this.receiveBuffer);
        if (this.receiveBuffer.length >= (2 + length)) {
          const data = this.receiveBuffer.slice(2, 2 + length);
          this.ringBuffer.push(data);
          this.receiveBuffer.consume(2 + length);
          return next();
        }
      }

      callback();
    };
    next();
  }
}

export function createPbStream() {
  return new PbStreamImpl();
}

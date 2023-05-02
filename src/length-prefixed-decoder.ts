import * as streams from 'stream';
import { Uint8ArrayList } from './uint8arraylist';
import { uint16BEDecode } from './encoder';

export class LengthPrefixedDecoder extends streams.Duplex {
  private readonly receiveBuffer = new Uint8ArrayList();
  private nextWrite: Function | null = null;

  constructor(options?: streams.DuplexOptions) {
    super({
      autoDestroy: true,
      ...options
    });
  }

  _read(size: number) {
    const nextWrite = this.nextWrite;
    this.nextWrite = null;
    if (nextWrite) {
      nextWrite();
    }
  }

  _write(chunk: any, encoding: BufferEncoding, callback: (error?: (Error | null)) => void) {
    this.receiveBuffer.append(chunk);

    const next = (): void => {
      if (this.receiveBuffer.length >= 2) {
        const length = uint16BEDecode(this.receiveBuffer);
        if (this.receiveBuffer.length >= (2 + length)) {
          const data = this.receiveBuffer.slice(2, 2 + length);
          this.receiveBuffer.consume(2 + length);
          if (this.push(data)) {
            setImmediate(next);
          } else {
            this.nextWrite = next;
          }
          return ;
        }
      }

      callback();
    };
    next();
  }
}

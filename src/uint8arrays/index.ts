import { compare } from './compare';
import { concat } from './concat';
import { equals } from './equals';
import { xor } from './xor';

export {
  compare,
  concat,
  equals,
  xor
};

export function fromString(input: string, encoding: BufferEncoding): Uint8Array {
  return Buffer.from(input, encoding);
}

export class Writer {
  private readonly chunks: Uint8Array[] = [];

  u8(n: number): this {
    this.chunks.push(Uint8Array.from([n & 0xff]));
    return this;
  }

  u32le(n: number): this {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n >>> 0, true);
    this.chunks.push(b);
    return this;
  }

  u64le(n: bigint): this {
    if (n < 0n || n > 0xffffffffffffffffn) throw new Error('u64 out of range');
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, n, true);
    this.chunks.push(b);
    return this;
  }

  varint(n: bigint): this {
    if (n < 0n) throw new Error('varint negative');
    let v = n;
    while (true) {
      let byte = Number(v & 0x7fn);
      v >>= 7n;
      if (v !== 0n) byte |= 0x80;
      this.u8(byte);
      if (v === 0n) break;
    }
    return this;
  }

  bytes(b: Uint8Array): this {
    this.chunks.push(b);
    return this;
  }

  varbytes(b: Uint8Array): this {
    this.varint(BigInt(b.length));
    this.bytes(b);
    return this;
  }

  finish(): Uint8Array {
    const total = this.chunks.reduce((n, c) => n + c.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of this.chunks) {
      out.set(c, off);
      off += c.length;
    }
    return out;
  }
}

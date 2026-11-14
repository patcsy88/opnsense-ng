import { createHmac } from "node:crypto";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(input: string): Buffer {
  let bits = "";
  for (const ch of input.replace(/=+$/, "").toUpperCase()) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error("bad base32");
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8)
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

function codeAt(secret: string, step: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const digest = createHmac("sha1", base32Decode(secret)).update(msg).digest();
  const offset = (digest[digest.length - 1] ?? 0) & 0x0f;
  const value = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(value % 1_000_000).padStart(6, "0");
}

/** Produces codes the server has not seen yet. The server accepts each time step once and
 * tolerates one step of drift, so this uses the earliest unused step in that window and waits
 * for the next step only when all three are used. */
export class Totp {
  private last = -1;
  constructor(private readonly secret: string) {}

  async next(): Promise<string> {
    for (;;) {
      const now = Math.floor(Date.now() / 30_000);
      for (const step of [now - 1, now, now + 1]) {
        if (step > this.last) {
          this.last = step;
          return codeAt(this.secret, step);
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 2_000));
    }
  }
}

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { p2pkhScriptPubKeyHexFromAddress, scriptHashHex } from '../src/script/index.js';

const vectors = JSON.parse(
  readFileSync(join(process.cwd(), 'test-vectors', 'vectors.json'), 'utf8'),
) as {
  script: { address: string; script_pubkey_hex: string; scripthash_hex: string };
};

describe('script and scripthash', () => {
  it('matches P2PKH script vector', () => {
    expect(p2pkhScriptPubKeyHexFromAddress(vectors.script.address)).toBe(vectors.script.script_pubkey_hex);
  });

  it('matches single-SHA256 scripthash vector', () => {
    expect(scriptHashHex(vectors.script.script_pubkey_hex)).toBe(vectors.script.scripthash_hex);
  });
});

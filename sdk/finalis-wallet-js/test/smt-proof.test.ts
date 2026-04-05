import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import { verifySmtProof } from '../src/proofs/smt.js';

type Vector = {
  name: string;
  root_hex: string;
  key_hex: string;
  value_hex: string | null;
  siblings: string[];
};

const vectors: Vector[] = JSON.parse(
  readFileSync(resolve(process.cwd(), 'test-vectors/smt_vectors.json'), 'utf8'),
) as Vector[];

describe('smt proof vectors', () => {
  it('verifies all shared vectors', () => {
    for (const v of vectors) {
      expect(verifySmtProof(v.root_hex, v.key_hex, v.value_hex, v.siblings), v.name).toBe(true);
    }
  });
});


import nacl from 'tweetnacl';
import { bytesToHex, hexToBytes } from './hash.js';

export interface Ed25519Keypair {
  privkeyHex: string;
  pubkeyHex: string;
}

export function keypairFromSeed32(seed: Uint8Array): Ed25519Keypair {
  if (seed.length !== 32) throw new Error('seed must be 32 bytes');
  const kp = nacl.sign.keyPair.fromSeed(seed);
  return {
    privkeyHex: bytesToHex(seed),
    pubkeyHex: bytesToHex(kp.publicKey),
  };
}

export function keypairFromPrivkeyHex(privkeyHex: string): Ed25519Keypair {
  const seed = hexToBytes(privkeyHex);
  if (seed.length !== 32) throw new Error('private key must be 32 bytes hex');
  return keypairFromSeed32(seed);
}

export function signEd25519(message: Uint8Array, privkeyHex: string): Uint8Array {
  const seed = hexToBytes(privkeyHex);
  if (seed.length !== 32) throw new Error('private key must be 32 bytes hex');
  const kp = nacl.sign.keyPair.fromSeed(seed);
  const sig = nacl.sign.detached(message, kp.secretKey);
  return sig;
}

export function verifyEd25519(message: Uint8Array, signatureHex: string, pubkeyHex: string): boolean {
  const sig = hexToBytes(signatureHex);
  const pub = hexToBytes(pubkeyHex);
  if (sig.length !== 64 || pub.length !== 32) return false;
  return nacl.sign.detached.verify(message, sig, pub);
}

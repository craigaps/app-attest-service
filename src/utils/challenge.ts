import crypto from 'node:crypto';

/**
 * Generates a random 32-byte challenge and returns it as a base64url string.
 */
export function generateChallenge(): string {
  const challenge = crypto.randomBytes(32);
  console.info('🎯 [Challenge] Generated challenge:', challenge.toString('base64url'));
  return challenge.toString('base64url');
}

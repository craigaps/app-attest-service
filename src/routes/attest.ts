import express, { Request, Response } from 'express';
import { generateChallenge } from '../utils/challenge';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { verifyAssertionObject, verifyAttestationObject } from '../utils/attestationHelpers';
import { getAttestationRecord, saveAttestationRecord } from '../utils/storage';

const router = express.Router();

/**
 * GET /attest/challenge
 * Returns a new base64url-encoded challenge.
 */
router.get('/challenge', (_req: Request, res: Response) => {
  const challenge = generateChallenge();
  res.json({ challenge });
});

/**
 * POST /attest/validate
 * Validates the attestation object using Apple’s endpoint and local checks.
 */
router.post('/validate', async (req: Request, res: Response) => {
  const { attestation, keyId, clientDataHash, appId, userId } = req.body;

  if (!attestation || !keyId || !clientDataHash || !appId || !userId) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    console.info('🚦 Starting attestation verification...');

    // Path to Apple root certificate (from env)
    // Reconstruct __dirname for ES modules
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);
    const trustedRootPath = join(__dirname, '../certs', process.env.APPLE_APP_ATTEST_CERTIFICATE!);

    // Get the environment from the .env file
    const environment = process.env.APPLE_APP_ATTEST_ENVIRONENT === 'production' ? 'production' : 'development';

    // Use the new helper for full validation
    const publicKey = await verifyAttestationObject(attestation, clientDataHash, keyId, appId, trustedRootPath, environment);

    // Save the attestation record in memory
    saveAttestationRecord(userId, keyId, publicKey, environment);

    console.info('✅ Attestation validated successfully');
    res.json({
      result: keyId
    });
  } catch (err: any) {
    console.error('❌ Attestation validation failed:', err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /attest/verify
 * Verifies the assertion object using Apple’s endpoint and local checks.
 */
router.post('/verify', async (req: Request, res: Response) => {
  const { assertion, keyId, clientDataHash, appId, challenge } = req.body;

  if (!assertion || !keyId || !clientDataHash || !appId || !challenge) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    console.info('🚦 Starting assertion verification...');

    // Get the environment from the .env file
    const environment = process.env.APPLE_APP_ATTEST_ENVIRONENT === 'production' ? 'production' : 'development';

    // Get the publicKey from the attestation record
    const attestationRecord = getAttestationRecord(keyId);
    if (!attestationRecord) {
        console.error('❌ No attestation record found for this keyId');
        return res.status(400).json({ error: 'No attestation record found for this keyId' });
    }
    console.info('🔍 Found attestation record:', attestationRecord);

    // Use the new helper for full validation
    const counter = await verifyAssertionObject(assertion, challenge, attestationRecord.publicKey, appId, attestationRecord?.counter);

    // Update the attestation record in memory
    saveAttestationRecord(attestationRecord?.userId, keyId, attestationRecord?.publicKey, environment);

    console.info('✅ Assertion validated successfully');
    res.json({
      result: counter.toString()
    });
  } catch (err: any) {
    console.error('❌ e validation failed:', err);
    res.status(500).json({ error: err.message });
  }
});

export default router;

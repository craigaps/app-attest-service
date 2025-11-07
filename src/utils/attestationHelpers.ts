import crypto from 'crypto';
import { X509Certificate, X509ChainBuilder } from '@peculiar/x509';
import cbor from 'cbor';
import fs from 'fs';

/**
 * 🔍 Extracts the Apple-defined nonce from the attestation certificate's extension.
 *
 * The extension uses OID: 1.2.840.113635.100.8.2
 * Expected value is SHA256(authData || clientDataHash)
 *
 * @param cert - Leaf attestation certificate (x5c[0])
 * @returns 32-byte nonce buffer
 * @throws If extension is missing or malformed
 */
export function extractNonceFromCert(cert: X509Certificate): Buffer {
  console.debug('🔍 Searching for nonce extension in attestation certificate...');
  const ext = cert.extensions.find(e => e.type === '1.2.840.113635.100.8.2');
  if (!ext || !ext.value) {
    console.error('❌ Nonce extension not found in certificate');
    throw new Error('Missing nonce extension');
  }
  const nonce = Buffer.from(ext.value).subarray(-32);
  console.debug('✅ Nonce extracted');
  return nonce;
}

/**
 * 🧮 Computes SHA256(authData || clientDataHash)
 *
 * This value should match the nonce embedded in the attestation certificate.
 *
 * @param authData - Raw authenticatorData buffer
 * @param clientDataHash - SHA256 hash of your challenge
 * @returns 32-byte buffer representing the expected nonce
 */
export function computeNonce(authData: Buffer, clientDataHash: Buffer): Buffer {
  console.debug('🧮 Computing nonce: SHA256(authData + clientDataHash)...');
  const payload = Buffer.concat([authData, clientDataHash]);
  const nonce = crypto.createHash('sha256').update(payload).digest();
  console.debug('✅ Nonce computed');
  return nonce;
}

/**
 * 🔐 Validates the attestation certificate chain against Apple’s trusted root.
 *
 * @param leafCert - Leaf certificate (x5c[0])
 * @param intermediates - Array of intermediate cert buffers
 * @param trustedRootPem - PEM-formatted Apple root certificate
 * @throws If the chain is invalid
 */
export async function verifyCertificateChain(leafCert: X509Certificate, intermediates: Buffer[], trustedRootPem: X509Certificate): Promise<void> {
  console.debug('🔗 Verifying certificate chain...');
  const builder = new X509ChainBuilder();
  builder.certificates.push(leafCert);
  intermediates.forEach((buf, i) => {
    console.debug(`🔗 Adding intermediate certificate [${i}]`);
    builder.certificates.push(new X509Certificate(buf));
  });
  builder.certificates.push(trustedRootPem);

  const result = await builder.build(leafCert);
  if (!result) {
    console.error('❌ Certificate chain validation failed');
    throw new Error('Certificate chain is invalid');
  }
  console.debug('✅ Certificate chain verified');
}

/**
 * 📤 Extracts and returns the COSE-encoded public key from authenticatorData.
 *
 * This is the public key generated on the device.
 *
 * @param authData - Raw authenticatorData buffer
 * @returns base64url-encoded COSE public key string
 */
export function extractPublicKey(authData: Buffer): string {
  console.debug('📤 Extracting public key from authenticatorData...');
  const attested = authData.subarray(37); // Skip RP ID (32), flags (1), counter (4)
  const credIdLen = attested.readUInt16BE(16);
  const pubKeyStart = 18 + credIdLen;
  const pubKeyBuf = attested.subarray(pubKeyStart);
  console.debug('✅ Public key extracted');
  return pubKeyBuf.toString('base64url');
}

/**
 * 🔑 Verifies that the keyId equals SHA256(publicKey from attestation cert).
 *
 * @param keyId - base64url-encoded key ID
 * @param cert - Attestation certificate
 * @throws If the keyId doesn't match
 */
export function verifyKeyIdMatchesPublicKey(keyId: string, cert: X509Certificate): void {
  console.debug('🔑 Verifying keyId matches public key...');
  // 1. Extract raw EC public key point (uncompressed)
  const pubKeyBuf = Buffer.from(cert.publicKey.rawData);

  // Check for X9.62 uncompressed format
  const x962PubKey = extractX962FromDer(pubKeyBuf);
  
  // Hash it
  const pubKeyHash = crypto.createHash('sha256')
    .update(x962PubKey)
    .digest('base64');

  if (pubKeyHash !== keyId) {
    console.error('❌ keyId mismatch');
    throw new Error('The keyId does not match the public key in certificate');
  }

  console.info('✅ keyId matches the credential certificate’s public key');
}

/**
 * Extracts EC public key in X9.62 uncompressed format from raw ASN.1 encoding
 *
 * @param derBuf - Buffer from cert.publicKey.rawData
 * @returns 65-byte EC point (starts with 0x04)
 * @throws If not properly formatted
 */
export function extractX962FromDer(derBuf: Buffer): Buffer {
  // Search for uncompressed point prefix (0x04)
  const idx = derBuf.indexOf(0x04);
  if (idx === -1 || derBuf.length < idx + 65) {
    throw new Error('X9.62 point not found in public key');
  }
  return derBuf.subarray(idx, idx + 65);
}

/**
 * 🧩 Verifies that RP ID hash matches SHA256(App ID)
 *
 * @param authData - authenticatorData buffer
 * @param appId - Your app’s bundle ID (e.g., com.example.myapp)
 * @throws If RP ID hash mismatch
 */
export function verifyRpIdHash(authData: Buffer, appId: string): void {
  console.debug('🧩 Verifying RP ID hash matches App ID...');
  const expectedHash = crypto.createHash('sha256').update(appId).digest();
  const rpIdHash = authData.subarray(0, 32);
  if (!rpIdHash.equals(expectedHash)) {
    console.error('❌ RP ID hash mismatch');
    throw new Error('RP ID hash does not match App ID');
  }
  console.debug('✅ RP ID hash verified');
}

/**
 * 🔢 Verifies counter field equals zero during attestation.
 *
 * @param authData - Raw authenticatorData buffer
 * @throws If counter is non-zero
 */
export function verifyCounterIsZero(authData: Buffer): void {
  console.debug('🔢 Verifying counter field...');
  const counter = authData.readUInt32BE(33);
  if (counter !== 0) {
    console.error(`❌ Counter expected 0, got ${counter}`);
    throw new Error('Counter must be 0 during attestation');
  }
  console.debug('✅ Counter field is 0');
}

/**
 * 🧬 Verifies AAGUID matches expected value for dev or prod.
 *
 * @param authData - Raw authenticatorData
 * @param environment - 'development' or 'production'
 * @throws If AAGUID doesn't match
 */
export function verifyAAGUID(authData: Buffer, environment: 'development' | 'production'): void {
  console.debug('🧬 Verifying AAGUID...');
  const aaguid = authData.subarray(37, 53);
  const expected = environment === 'development'
    ? Buffer.from('appattestdevelop', 'utf8')
    : Buffer.concat([Buffer.from('appattest', 'utf8'), Buffer.alloc(7, 0)]);

  if (!aaguid.equals(expected)) {
    console.error('❌ AAGUID mismatch');
    throw new Error(`Invalid AAGUID for ${environment} environment`);
  }
  console.debug('✅ AAGUID matches');
}

/**
 * 🧷 Verifies credentialId === keyId
 *
 * @param authData - Raw authenticatorData
 * @param keyId - base64url-encoded key ID
 * @throws If credential ID doesn't match keyId
 */
export function verifyCredentialIdMatchesKeyId(authData: Buffer, keyId: string): void {
  console.debug('🧷 Verifying credentialId matches keyId...');
  const attested = authData.subarray(37);
  const credIdLen = attested.readUInt16BE(16);
  const credId = attested.subarray(18, 18 + credIdLen);
  const keyIdBuf = Buffer.from(keyId, 'base64url');
  if (!credId.equals(keyIdBuf)) {
    console.error('❌ credentialId mismatch');
    throw new Error('credentialId does not match keyId');
  }
  console.debug('✅ credentialId matches keyId');
}

/**
 * Converts a raw X9.62 uncompressed EC public key to PEM format (SPKI).
 *
 * @param rawKey - 65-byte Buffer starting with 0x04
 * @returns PEM-encoded public key string
 * @throws If the key is not valid X9.62 format
 */
export function convertX962ToPem(rawKey: Buffer): string {
  console.debug(`🔍 Converting raw public key to PEM...`);
  console.debug(`📏 Key length: ${rawKey.length}`);
  console.debug(`🔢 First byte: 0x${rawKey[0]?.toString(16)}`);

  if (rawKey.length !== 65 || rawKey[0] !== 0x04) {
    console.error('❌ Invalid X9.62 uncompressed EC public key');
    throw new Error('Invalid X9.62 uncompressed EC public key');
  }

  const spkiHeader = Buffer.from([
    0x30, 0x59,
    0x30, 0x13,
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00,
  ]);

  const der = Buffer.concat([spkiHeader, rawKey]);
  const base64 = der.toString('base64');
  const pem = `-----BEGIN PUBLIC KEY-----\n${base64.match(/.{1,64}/g)?.join('\n')}\n-----END PUBLIC KEY-----`;

  console.debug('✅ PEM conversion complete');
  return pem;
}

/**
 * Decodes a COSE-encoded EC public key (from attestation) into X9.62 format.
 *
 * @param coseKeyBuf - Buffer containing COSE key
 * @returns 65-byte Buffer in X9.62 uncompressed format
 */
export function decodeCosePublicKey(coseKeyBuf: Buffer): Buffer {
  const coseStruct = cbor.decodeFirstSync(coseKeyBuf);

  const x = coseStruct.get(-2); // x-coordinate
  const y = coseStruct.get(-3); // y-coordinate

  if (!x || !y) {
    throw new Error('Invalid COSE key: missing x or y coordinates');
  }

  // X9.62 uncompressed point format: 0x04 || X || Y
  return Buffer.concat([Buffer.from([0x04]), x, y]);
}

/**
 * 📂 Loads an Apple trusted root certificate from a PEM-encoded file.
 *
 * Reads a PEM-formatted certificate from disk and parses it
 * into an `X509Certificate` instance for use in certificate chain validation.
 * Commonly used when validating an App Attest `attestationObject` against
 * Apple’s published root certificate: Apple_App_Attestation_Root_CA.pem
 *
 * @param path - Absolute or relative file path to the PEM certificate
 * @returns Parsed X509Certificate instance
 * @throws If the file cannot be read or the PEM is invalid
 */
export function loadRootCertificateFromFile(path: string): X509Certificate {
  console.info(`[Attestation] 📥 Reading trusted root certificate from: ${path}`);
  const pemContents = fs.readFileSync(path, 'utf-8');
  const cert = new X509Certificate(pemContents);
  console.info('[Attestation] ✅ Trusted root certificate successfully loaded');
  return cert;
}

/**
 * 🎁 Full Attestation Verifier for Apple DeviceCheck
 *
 * @param attestationObjectB64 - base64url-encoded CBOR attestationObject
 * @param clientDataHashB64 - base64url-encoded SHA256(challenge)
 * @param keyId - base64url-encoded key ID from generateKey()
 * @param appId - Your app's bundle ID (e.g., com.example.myapp)
 * @param trustedRootPath - Apple App Attest Root PEM cert path
 * @param environment - "development" or "production"
 * @returns Base64url-encoded public key string from authenticatorData
 * @throws If any validation fails
 */
export async function verifyAttestationObject(attestationObjectB64: string, clientDataHashB64: string, keyId: string, appId: string, trustedRootPath: string, environment: 'development' | 'production'): Promise<string> {
  console.info('🚦 Starting attestation object verification...');
  const attestationBuf = Buffer.from(attestationObjectB64, 'base64url');
  const clientHashBuf = Buffer.from(clientDataHashB64, 'base64url');

  // Step 1: Decode the CBOR attestation object
  console.debug('🧾 Decoding CBOR attestationObject...');
  const { fmt, authData, attStmt } = await cbor.decodeFirst(attestationBuf);

  // Step 2: Check format
  if (fmt !== 'apple-appattest') {
    throw new Error(`Unsupported attestation format: ${fmt}`);
  }
  const authBuf = authData as Buffer;
  const x5cChain = attStmt['x5c'];
  if (!Array.isArray(x5cChain) || x5cChain.length === 0) {
    throw new Error('Missing x5c certificate chain');
  }

  // Step 3: Parse certificates
  const leafCert = new X509Certificate(x5cChain[0]);
  const intermediateCerts = x5cChain.slice(1);

  // Step 4: Nonce Verification
  const expectedNonce = computeNonce(authBuf, clientHashBuf);
  const actualNonce = extractNonceFromCert(leafCert);
  if (!expectedNonce.equals(actualNonce)) {
    throw new Error('Nonce mismatch: computed nonce does not match certificate nonce');
  }

  // Step 5: Certificate Chain Validation
  const trustedRootPem = loadRootCertificateFromFile(trustedRootPath);
  await verifyCertificateChain(leafCert, intermediateCerts, trustedRootPem);

  // Step 6: Check root certificate subject CN
  if (!trustedRootPem.subject.includes('CN=Apple App Attestation Root CA')) {
    throw new Error('Root certificate subject CN is not "Apple App Attestation Root CA"');
  }

  // Step 7: Verify keyId matches publicKey in leaf cert
  verifyKeyIdMatchesPublicKey(keyId, leafCert);

  // Step 8: Verify RP ID hash matches SHA256(App ID)
  verifyRpIdHash(authBuf, appId);

  // Step 9: Verify counter == 0
  verifyCounterIsZero(authBuf);

  // Step 10: Verify AAGUID matches expected value
  verifyAAGUID(authBuf, environment);

  // Step 11: Verify credentialId === keyId
  verifyCredentialIdMatchesKeyId(authBuf, keyId);

  // Step 12: Return attested public key
  const publicKey = extractPublicKey(authBuf);

  console.info('✅ Attestation verified successfully');
  return publicKey;
}

/**
 * Verifies an App Attest assertion object.
 *
 * @param assertionB64 - base64url-encoded CBOR assertion object
 * @param clientDataJSON - original clientData JSON string sent by the app
 * @param storedPublicKey - COSE or PEM-encoded public key from attestation
 * @param appId - Your App ID (e.g., TEAMID.com.example.app)
 * @param previousCounter - Last known counter value for this keyId
 * @returns The new counter value if verification succeeds
 * @throws If any validation step fails
 */
export async function verifyAssertionObject(assertionB64: string, challenge: string, storedPublicKey: string, appId: string, previousCounter: number): Promise<number> {
  console.info('🔐 Verifying App Attest assertion...');

  // Step 1: Decode CBOR assertion
  const assertionBuf = Buffer.from(assertionB64, 'base64url');
  const decoded = await cbor.decodeFirst(assertionBuf);
  const { authenticatorData, signature } = decoded;

  if (!authenticatorData || !signature) {
    throw new Error('Invalid assertion format: missing authenticatorData or signature');
  }

  const authDataBuf = Buffer.from(authenticatorData);
  const signatureBuf = Buffer.from(signature);

  // Step 2: Compute SHA256(challenge)
  const challengeHash = crypto.createHash('sha256')
    .update(challenge)
    .digest();
  console.debug(`🔐 SHA256(challenge): ${challengeHash.toString('hex')}`);

  // Step 3: Compute nonce = SHA256(authData || challengeHash)
  const nonce = crypto.createHash('sha256')
    .update(Buffer.concat([authDataBuf, challengeHash]))
    .digest();
  console.debug(`🔐 Nonce: ${nonce.toString('hex')}`);

  // Step 4: Convert public key to PEM
  const coseKeyBuf = Buffer.from(storedPublicKey, 'base64url');
  const x962Key = decodeCosePublicKey(coseKeyBuf);
  const pem = convertX962ToPem(x962Key);

  // Step 5: Verify signature
  const isValid = crypto.verify(
    null,
    nonce,
    {
      key: pem,
      format: 'pem',
      type: 'spki',
    },
    signatureBuf
  );

  if (!isValid) {
    throw new Error('❌ Signature verification failed');
  }
  console.debug('✅ Signature verified');

  // Step 6: Verify RP ID hash matches SHA256(App ID)
  const rpIdHash = authDataBuf.subarray(0, 32);
  const expectedRpIdHash = crypto.createHash('sha256').update(appId).digest();
  if (!rpIdHash.equals(expectedRpIdHash)) {
    throw new Error('❌ RP ID hash mismatch');
  }
  console.debug('✅ RP ID hash verified');

  // Step 7: Verify counter is increasing
  const counter = authDataBuf.readUInt32BE(33);
  if (previousCounter > 0 && counter <= previousCounter) {
    throw new Error(`❌ Counter did not increase (got ${counter}, expected > ${previousCounter})`);
  }
  console.debug(`✅ Counter is valid: ${counter}`);

  return counter;
}
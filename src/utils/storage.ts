/**
 * Represents a validated App Attest key record.
 */
export interface AttestationRecord {
  /** Unique identifier for the user or device */
  userId: string;

  /** base64url-encoded keyId returned by generateKey() */
  keyId: string;

  /** base64url-encoded COSE public key */
  publicKey: string;

  /** App Attest environment: 'development' or 'production' */
  environment: 'development' | 'production';

  /** Timestamp of the most recent successful attestation */
  lastAttestDate: Date;

  /** Timestamp when the key was first registered */
  createdAt: Date;

  /** Whether the key has been revoked */
  revoked: boolean;

  /**
   * The latest authenticator counter value for this key.
   * This should be updated after each successful assertion.
   * Used to detect replay attacks (counter must always increase).
   */
  counter: number;
}

const attestationMap = new Map<string, AttestationRecord>();

/**
 * Saves or updates an attestation record in memory.
 *
 * If the keyId already exists, it updates the lastAttestDate and clears revocation.
 * If it doesn't exist, it creates a new record.
 * If called for an assertion (not attestation), only userId, keyId, and environment are required.
 *
 * @param userId - Unique identifier for the user
 * @param keyId - base64url-encoded keyId from generateKey()
 * @param publicKey - base64url-encoded COSE public key (optional for assertion)
 * @param environment - 'development' or 'production'
 */
export function saveAttestationRecord(userId: string, keyId: string, publicKey: string | undefined, environment: 'development' | 'production'): void {
  const now = new Date();

  const existing = attestationMap.get(keyId);
  if (existing) {
    console.log(`🔁 Updating attestation record for keyId: ${keyId}`);
    existing.lastAttestDate = now;
    existing.revoked = false;
    
    // Optionally update environment if changed
    existing.environment = environment;

    // Increment the counter for each successful attestation
    existing.counter += 1;

    // Only update publicKey if provided (for attestation)
    if (publicKey) {
      existing.publicKey = publicKey;
    }
  } 
  else {
    console.log(`🆕 Creating new attestation record for keyId: ${keyId}`);
    attestationMap.set(keyId, {
      userId,
      keyId,
      publicKey: publicKey || '',
      environment,
      lastAttestDate: now,
      createdAt: now,
      revoked: false,
      counter: 0, // Initialize counter to 0
    });
  }
}

/**
 * Retrieves an attestation record by keyId.
 *
 * @param keyId - base64url-encoded keyId
 * @returns The matching AttestationRecord, or undefined if not found
 */
export function getAttestationRecord(keyId: string): AttestationRecord | undefined {
  return attestationMap.get(keyId);
}

/**
 * Marks an attestation key as revoked.
 *
 * This is useful for invalidating keys that fail assertion validation
 * or are suspected of compromise.
 *
 * @param keyId - base64url-encoded keyId
 */
export function revokeAttestationKey(keyId: string): void {
  const record = attestationMap.get(keyId);
  if (record) {
    record.revoked = true;
    console.warn(`🚫 Key revoked: ${keyId}`);
  }
}

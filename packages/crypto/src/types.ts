/**
 * Cryptographic algorithm identifiers
 */
export type CryptoAlgorithm =
  | 'ml-dsa-65'      // FIPS 204 - Primary PQC signature
  | 'ml-dsa-87'      // FIPS 204 - Higher security PQC signature
  | 'slh-dsa-sha2-128f' // FIPS 205 - Stateless hash-based (conservative fallback)
  | 'ml-kem-768'     // FIPS 203 - Key encapsulation
  | 'ml-kem-1024'    // FIPS 203 - Higher security KEM
  | 'ecdsa-p256'     // Classical ECDSA (for hybrid mode)
  | 'ed25519';       // Classical EdDSA (for hybrid mode)

/**
 * Cryptographic operation mode
 */
export type CryptoMode =
  | 'pqc-only'       // Post-quantum only (ML-DSA + ML-KEM)
  | 'hybrid'         // PQC + Classical (recommended for transition period)
  | 'classical-only'; // Classical only (for legacy compatibility)

/**
 * Configuration for AstraCipher crypto operations
 */
export interface CryptoConfig {
  /** Operation mode - hybrid recommended */
  mode: CryptoMode;
  /** Signature algorithm */
  signatureAlgorithm: CryptoAlgorithm;
  /** Classical signature algorithm (used in hybrid mode) */
  classicalSignatureAlgorithm: CryptoAlgorithm;
  /** Key encapsulation algorithm */
  kemAlgorithm: CryptoAlgorithm;
  /** Key derivation iterations */
  kdfIterations: number;
  /** Whether to include algorithm identifiers in output */
  includeAlgorithmId: boolean;
}

/**
 * Default configuration: hybrid mode with ML-DSA-65 + ECDSA P-256
 */
export const DEFAULT_CONFIG: CryptoConfig = {
  mode: 'hybrid',
  signatureAlgorithm: 'ml-dsa-65',
  classicalSignatureAlgorithm: 'ecdsa-p256',
  kemAlgorithm: 'ml-kem-768',
  kdfIterations: 100_000,
  includeAlgorithmId: true,
};

/**
 * Serialized key format for storage/transmission
 */
export interface SerializedKey {
  algorithm: CryptoAlgorithm;
  publicKey: string;   // base64url encoded
  secretKey?: string;  // base64url encoded (omitted for public-only)
  keyId: string;       // unique key identifier
  createdAt: string;   // ISO 8601
  expiresAt?: string;  // ISO 8601
}

/**
 * Serialized hybrid key pair
 */
export interface SerializedHybridKeyPair {
  pqc: SerializedKey;
  classical: SerializedKey;
  mode: CryptoMode;
  keyId: string;
}

'use server'

import prisma from "@/lib/prisma"
import { 
  decryptData, 
  encryptData, 
  upsertEncryptionKey, 
  upsertKyberKey,
  validateEncryptionAlgorithm,
  type EncryptionAlgorithm 
} from "./encryption"
import { cookies } from "next/headers"
import { type DecryptedPassword, verifyToken } from "./helpers"

// Helper to normalize public key to Uint8Array
function normalizePublicKey(
  pubKey: string | Buffer | Uint8Array | { type: string; data: number[] }
): Uint8Array {
  // Handle object with Buffer-like structure (e.g., { type: 'Buffer', data: [...] })
  if (
    pubKey &&
    typeof pubKey === "object" &&
    (pubKey as any).type === "Buffer" &&
    Array.isArray((pubKey as any).data)
  ) {
    return Uint8Array.from((pubKey as any).data);
  }

  if (typeof pubKey === "string") {
    const trimmed = pubKey.trim();
    // PEM-like string: contains header/footer lines
    if (trimmed.includes("-----BEGIN")) {
      // Remove PEM header/footer and whitespace
      const base64Body = trimmed
        .replace(/-----BEGIN [^-]+-----/, "")
        .replace(/-----END [^-]+-----/, "")
        .replace(/\s+/g, "");
      return Uint8Array.from(Buffer.from(base64Body, "base64"));
    }
    // Comma-separated numeric values (e.g., "1,2,3,4")
    if (/^\d+(,\d+)*$/.test(trimmed)) {
      const arr = trimmed.split(",").map((v) => parseInt(v, 10));
      return Uint8Array.from(arr);
    }
    // Hex string
    if (/^[0-9a-fA-F]+$/.test(trimmed)) {
      if (trimmed.length % 2 !== 0) {
        throw new Error(`Invalid hex public key length (odd): ${trimmed.length}`);
      }
      return Uint8Array.from(Buffer.from(trimmed, "hex"));
    }
    // Base64 string
    if (/^[A-Za-z0-9+/=]+$/.test(trimmed) && trimmed.length % 4 === 0) {
      return Uint8Array.from(Buffer.from(trimmed, "base64"));
    }
    throw new Error("Unrecognized public key format");
  } else if (Buffer.isBuffer(pubKey)) {
    return Uint8Array.from(pubKey);
  } else if (pubKey instanceof Uint8Array) {
    return pubKey;
  }
  throw new Error("Unsupported public key type");
}
function assertKyberPublicKeyLength(pubKeyBytes: Uint8Array, variant = "kyber-768") {
  let expectedBytes: number | null = null;
  if (variant === "kyber-768") {
    expectedBytes = 2368;
  } else if (variant === "kyber-512") {
    expectedBytes = 1184;
  }
  if (expectedBytes && pubKeyBytes.length !== expectedBytes) {
    throw new Error(`Kyber public key length mismatch: got ${pubKeyBytes.length}, expected ${expectedBytes}`);
  }
}

export async function verifyAuth(): Promise<string | null> {
  const token = (await cookies()).get('auth-token')
  if (!token) { 
    return null
  }

  const decoded = verifyToken(token.value)
  if (!decoded || !decoded.userId) {
    return null
  }

  return decoded.userId
}

/**
 * Stores an encrypted password for a user with enhanced algorithm support
 */
export async function storePassword(password: {
  service: string,
  username: string,
  password: string,
  algorithm?: string
}) {
  const authenticatedUserId = await verifyAuth()
  if (!authenticatedUserId) {
    throw new Error("Unauthorized")
  }

  // Validate algorithm
  const algorithm = password.algorithm || 'aes-256-gcm'
  const isValidAlgorithm = await validateEncryptionAlgorithm(algorithm)
  if (!isValidAlgorithm) {
    throw new Error(`Unsupported encryption algorithm: ${algorithm}`)
  }

  let encryptedData: string
  let iv: string
  let keyId: string | null = null
  let kyberKeyId: string | null = null
  let metadata: Record<string, any> | null = null

  try {
    // Prepare keys based on algorithm
    const keys: Record<string, string> = {}

    switch (algorithm) {
      case 'aes-256-gcm': {
        const aesKey = await upsertEncryptionKey(authenticatedUserId)
        keys.aesKey = aesKey.key
        keyId = aesKey.id
        break
      }
      case 'kyber-768': {
        const kyberKey = await upsertKyberKey(authenticatedUserId)
        console.log("DEBUG storePassword kyber publicKey:", kyberKey.publicKey, "type:", typeof kyberKey.publicKey);
        const pubKeyBytes = normalizePublicKey(kyberKey.publicKey);
        assertKyberPublicKeyLength(pubKeyBytes, "kyber-512");
        keys.kyberPublicKey = Buffer.from(pubKeyBytes).toString("hex");
        kyberKeyId = kyberKey.id
        break
      }
      case 'aes-256-gcm-hybrid': {
        const [aesKeyHybrid, kyberKeyHybrid] = await Promise.all([
          upsertEncryptionKey(authenticatedUserId),
          upsertKyberKey(authenticatedUserId)
        ])
        keys.aesKey = aesKeyHybrid.key
        console.log("DEBUG storePassword hybrid kyber publicKey:", kyberKeyHybrid.publicKey, "type:", typeof kyberKeyHybrid.publicKey);
        const pubKeyBytes = normalizePublicKey(kyberKeyHybrid.publicKey);
        assertKyberPublicKeyLength(pubKeyBytes, "kyber-512");
        keys.kyberPublicKey = Buffer.from(pubKeyBytes).toString("hex");
        keyId = aesKeyHybrid.id
        kyberKeyId = kyberKeyHybrid.id
        break
      }
      default:
        throw new Error(`Unsupported algorithm: ${algorithm}`)
    }

    // Encrypt the password
    const encryptionResult = await encryptData(password.password, algorithm as EncryptionAlgorithm, keys)
    encryptedData = encryptionResult.encryptedData
    iv = encryptionResult.iv
    metadata = encryptionResult.metadata || null

  } catch (error) {
    console.error('Password encryption failed:', error)
    throw new Error(`Failed to encrypt password: ${error instanceof Error ? error.message : 'Unknown error'}`)
  }

  // Store the encrypted password
  return prisma.password.create({
    data: {
      userId: authenticatedUserId,
      service: password.service,
      username: password.username,
      encryptedData: encryptedData,
      iv: iv,
      algorithm: algorithm,
      keyId: keyId,
      kyberKeyId: kyberKeyId,
      metadata: metadata ?? undefined
    }
  })
}

/**
 * Retrieves all passwords for a user
 */
export async function getPasswords() {
  const authenticatedUserId = await verifyAuth()
  if (!authenticatedUserId) {
    throw new Error("Unauthorized")
  }

  return prisma.password.findMany({
    where: {
      userId: authenticatedUserId
    },
    include: {
      key: true,
      kyberKey: true
    }
  })
}

/**
 * Retrieves passwords for a specific service
 */
export async function getPasswordsByService(userId: string, service: string) {
  return prisma.password.findMany({
    where: {
      userId: userId,
      service: service
    },
    include: {
      key: true,
      kyberKey: true
    }
  })
}

/**
 * Updates an existing password
 */
export async function updatePassword(
  passwordId: string,
  updates: {
    service?: string
    username?: string
    password?: string
    algorithm?: string
  }
) {
  const authenticatedUserId = await verifyAuth()
  if (!authenticatedUserId) {
    throw new Error("Unauthorized")
  }

  // If password is being updated, re-encrypt it
  if (updates.password) {
    const algorithm = updates.algorithm || 'aes-256-gcm'
    const isValidAlgorithm = await validateEncryptionAlgorithm(algorithm)
    if (!isValidAlgorithm) {
      throw new Error(`Unsupported encryption algorithm: ${algorithm}`)
    }

    // Prepare keys based on algorithm
    const keys: Record<string, string> = {}
    let keyId: string | null = null
    let kyberKeyId: string | null = null
    let metadata: Record<string, any> | null = null

    switch (algorithm) {
      case 'aes-256-gcm': {
        const aesKey = await upsertEncryptionKey(authenticatedUserId)
        keys.aesKey = aesKey.key
        keyId = aesKey.id
        break
      }
      case 'kyber-768': {
        const kyberKey = await upsertKyberKey(authenticatedUserId)
        console.log("DEBUG updatePassword kyber publicKey:", kyberKey.publicKey, "type:", typeof kyberKey.publicKey);
        const pubKeyBytes = normalizePublicKey(kyberKey.publicKey);
        assertKyberPublicKeyLength(pubKeyBytes, "kyber-512");
        keys.kyberPublicKey = Buffer.from(pubKeyBytes).toString("hex");
        kyberKeyId = kyberKey.id
        break
      }
      case 'aes-256-gcm-hybrid': {
        const [aesKeyHybrid, kyberKeyHybrid] = await Promise.all([
          upsertEncryptionKey(authenticatedUserId),
          upsertKyberKey(authenticatedUserId)
        ])
        keys.aesKey = aesKeyHybrid.key
        console.log("DEBUG updatePassword hybrid kyber publicKey:", kyberKeyHybrid.publicKey, "type:", typeof kyberKeyHybrid.publicKey);
        const pubKeyBytes = normalizePublicKey(kyberKeyHybrid.publicKey);
        assertKyberPublicKeyLength(pubKeyBytes, "kyber-512");
        keys.kyberPublicKey = Buffer.from(pubKeyBytes).toString("hex");
        keyId = aesKeyHybrid.id
        kyberKeyId = kyberKeyHybrid.id
        break
      }
      default:
        throw new Error(`Unsupported algorithm: ${algorithm}`)
    }

    // Encrypt the new password
    const encryptionResult = await encryptData(updates.password, algorithm as EncryptionAlgorithm, keys)
    
    return prisma.password.update({
      where: {
        id: passwordId,
        userId: authenticatedUserId
      },
      data: {
        ...updates,
        encryptedData: encryptionResult.encryptedData,
        iv: encryptionResult.iv,
        algorithm: algorithm,
        keyId: keyId,
        kyberKeyId: kyberKeyId,
        metadata: encryptionResult.metadata ?? undefined
      }
    })
  } else {
    // Update other fields without re-encryption
    return prisma.password.update({
      where: {
        id: passwordId,
        userId: authenticatedUserId
      },
      data: updates
    })
  }
}

/**
 * Deletes a password
 */
export async function deletePassword(passwordId: string) {
  const authenticatedUserId = await verifyAuth()
  if (!authenticatedUserId) {
    throw new Error("Unauthorized")
  }

  return prisma.password.delete({
    where: {
      id: passwordId,
      userId: authenticatedUserId
    }
  })
}

/**
 * Retrieves and decrypts all passwords for a user
 */
export async function getDecryptedPasswords(): Promise<DecryptedPassword[]> {
  const authenticatedUserId = await verifyAuth()
  if (!authenticatedUserId) {
    throw new Error("Unauthorized")
  }

  const encryptedPasswords = await prisma.password.findMany({
    where: {
      userId: authenticatedUserId
    },
    include: {
      key: true,
      kyberKey: true
    }
  })

  // Decrypt each password
  const decryptedPasswords = await Promise.all(
    encryptedPasswords.map(async (encPass) => {
      let decryptedPassword = ""
      let algorithm = encPass.algorithm

      try {
        // Validate algorithm
        if (!validateEncryptionAlgorithm(algorithm)) {
          throw new Error(`Unsupported algorithm: ${algorithm}`)
        }

        // Prepare keys for decryption
        const keys: Record<string, string> = {}

        switch (algorithm) {
          case 'aes-256-gcm':
            if (!encPass.key) {
              throw new Error("No AES encryption key found")
            }
            keys.aesKey = encPass.key.key
            break

          case 'kyber-768':
            if (!encPass.kyberKey) {
              throw new Error("No Kyber key found")
            }
            keys.kyberPrivateKey = (Buffer.isBuffer(encPass.kyberKey.privateKey)
              ? encPass.kyberKey.privateKey
              : new Uint8Array(encPass.kyberKey.privateKey as any))
              .toString('hex')
            break

          case 'aes-256-gcm-hybrid':
            if (!encPass.kyberKey) {
              throw new Error("No Kyber key found for hybrid decryption")
            }
            keys.kyberPrivateKey = (Buffer.isBuffer(encPass.kyberKey.privateKey)
              ? encPass.kyberKey.privateKey
              : new Uint8Array(encPass.kyberKey.privateKey as any))
              .toString('hex')
            break

          default:
            throw new Error(`Unsupported algorithm: ${algorithm}`)
        }

        // Decrypt the password
        const decryptionResult = await decryptData(
          encPass.encryptedData,
          encPass.iv,
          algorithm as EncryptionAlgorithm,
          keys
        )

        decryptedPassword = decryptionResult.decryptedData
        algorithm = decryptionResult.algorithm

      } catch (error) {
        console.error(`Decryption error for password ${encPass.id}:`, error)
        decryptedPassword = `[Decryption error: ${error instanceof Error ? error.message : 'Unknown error'}]`
      }

      return {
        id: encPass.id,
        service: encPass.service,
        username: encPass.username,
        password: decryptedPassword,
        algorithm: algorithm,
        createdAt: encPass.createdAt,
        updatedAt: encPass.updatedAt
      }
    })
  )

  return decryptedPasswords
}

/**
 * Get encryption statistics for a user
 */
export async function getEncryptionStats() {
  const authenticatedUserId = await verifyAuth()
  if (!authenticatedUserId) {
    throw new Error("Unauthorized")
  }

  const passwords = await prisma.password.findMany({
    where: {
      userId: authenticatedUserId
    },
    select: {
      algorithm: true
    }
  })

  const stats = passwords.reduce((acc, password) => {
    acc[password.algorithm] = (acc[password.algorithm] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  return {
    total: passwords.length,
    byAlgorithm: stats
  }
}

/**
 * Rotate encryption keys for a user
 */
export async function rotateEncryptionKeys() {
  const authenticatedUserId = await verifyAuth()
  if (!authenticatedUserId) {
    throw new Error("Unauthorized")
  }

  // Deactivate all existing keys
  await Promise.all([
    prisma.encryptionKey.updateMany({
      where: {
        userId: authenticatedUserId,
        active: true
      },
      data: {
        active: false
      }
    }),
    prisma.kyberKey.updateMany({
      where: {
        userId: authenticatedUserId,
        active: true
      },
      data: {
        active: false
      }
    })
  ])

  // Create new keys
  const [aesKey, kyberKey] = await Promise.all([
    upsertEncryptionKey(authenticatedUserId),
    upsertKyberKey(authenticatedUserId)
  ])

  return {
    aesKeyId: aesKey.id,
    kyberKeyId: kyberKey.id
  }
}
'use server'

import prisma from "@/lib/prisma"
import { verifyAuth } from "./password"
import crypto from "node:crypto"
import kyber from "crystals-kyber"

// Encryption algorithm types
export type EncryptionAlgorithm = 'aes-256-gcm' | 'kyber-768' | 'aes-256-gcm-hybrid'

// Encryption result interface
export interface EncryptionResult {
  encryptedData: string
  iv: string
  algorithm: EncryptionAlgorithm
  metadata?: Record<string, any>
}

// Decryption result interface
export interface DecryptionResult {
  decryptedData: string
  algorithm: EncryptionAlgorithm
}

/**
 * Enhanced AES-256-GCM encryption with proper error handling
 */
export async function encryptAES(data: string, keyString: string): Promise<{ encryptedData: string, iv: string }> {
  try {
    // Validate input
    if (!data || !keyString) {
      throw new Error("Invalid input: data and key are required")
    }

    // Generate a 12-byte IV for AES-GCM
    const iv = crypto.randomBytes(12)
    const keyBuffer = Buffer.from(keyString, 'base64')

    // Validate key length (should be 32 bytes for AES-256)
    if (keyBuffer.length !== 32) {
      throw new Error(`Invalid key length: ${keyBuffer.length}. Expected 32 bytes for AES-256`)
    }

    // Import the key
    const key = await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt']
    )

    // Encrypt the data
    const encodedData = new TextEncoder().encode(data)
    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      key,
      encodedData
    )

    return {
      encryptedData: Buffer.from(encryptedBuffer).toString('base64'),
      iv: Buffer.from(iv).toString('base64')
    }
  } catch (error) {
    console.error('AES encryption error:', error)
    throw new Error(`AES encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
  }
}

/**
 * Enhanced AES-256-GCM decryption with proper error handling
 */
export async function decryptAES(encryptedData: string, iv: string, keyString: string): Promise<string> {
  try {
    // Validate input
    if (!encryptedData || !iv || !keyString) {
      throw new Error("Invalid input: encryptedData, iv, and key are required")
    }

    // Convert base64 strings back to buffers
    const encryptedBuffer = Buffer.from(encryptedData, 'base64')
    const ivBuffer = Buffer.from(iv, 'base64')
    const keyBuffer = Buffer.from(keyString, 'base64')

    // Validate IV length (should be 12 bytes for AES-GCM)
    if (ivBuffer.length !== 12) {
      throw new Error(`Invalid IV length: ${ivBuffer.length}. Expected 12 bytes for AES-GCM`)
    }

    // Validate key length (should be 32 bytes for AES-256)
    if (keyBuffer.length !== 32) {
      throw new Error(`Invalid key length: ${keyBuffer.length}. Expected 32 bytes for AES-256`)
    }

    // Import the key
    const key = await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'AES-GCM', length: 256 },
      true,
      ['decrypt']
    )

    // Decrypt the data
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ivBuffer
      },
      key,
      encryptedBuffer
    )

    return new TextDecoder().decode(decryptedBuffer)
  } catch (error) {
    console.error('AES decryption error:', error)
    throw new Error(`AES decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
  }
}

/**
 * Kyber-768 post-quantum encryption
 */
export async function encryptKyber(data: string, publicKey: string): Promise<{ encryptedData: string, iv: string, metadata: Record<string, any> }> {
  try {
    // Validate input
    if (!data || !publicKey) {
      throw new Error("Invalid input: data and publicKey are required")
    }
    // Additional public key validation
    if (typeof publicKey !== 'string') {
      throw new Error(`Kyber public key must be a hex string, got type: ${typeof publicKey}`);
    }
    if (publicKey.length !== 1184 * 2) { // hex string length should be double the byte length
      throw new Error(`Kyber public key hex length mismatch: got ${publicKey.length}, expected ${1184 * 2}`);
    }

    // Parse the public key
    const pk = Buffer.from(publicKey, 'hex')
    
    // Validate public key length for Kyber-768
    if (pk.length !== 1184) {
      throw new Error(`Invalid Kyber-768 public key length: ${pk.length}. Expected 1184 bytes`)
    }

    // Encapsulate (generate shared secret and ciphertext)
    const [ciphertext, sharedSecret] = kyber.Encrypt768(pk)
    
    // Validate the shared secret
    if (!sharedSecret || sharedSecret.length < 32) {
      throw new Error("Invalid shared secret generated from Kyber encapsulation")
    }
    
    // Use shared secret as AES-256-GCM key
    const aesKey = sharedSecret.slice(0, 32) // 256 bits
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv)
    
    let encrypted = cipher.update(data, 'utf8', 'hex')
    encrypted += cipher.final('hex')
    const authTag = cipher.getAuthTag()
    
    // Store the encrypted data with Kyber metadata
    const encryptedData = JSON.stringify({
      encrypted,
      authTag: authTag.toString('hex'),
      kyberCiphertext: ciphertext.toString('hex'),
      algorithm: 'kyber-768'
    })
    
    return {
      encryptedData,
      iv: iv.toString('hex'),
      metadata: {
        kyberCiphertext: ciphertext.toString('hex'),
        algorithm: 'kyber-768'
      }
    }
  } catch (error) {
    console.error('Kyber encryption error:', error)
    throw new Error(`Kyber encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
  }
}

/**
 * Kyber-768 post-quantum decryption
 */
export async function decryptKyber(encryptedData: string, iv: string, privateKey: string): Promise<string> {
  try {
    // Validate input
    if (!encryptedData || !iv || !privateKey) {
      throw new Error("Invalid input: encryptedData, iv, and privateKey are required")
    }

    // Parse the encrypted data
    let parsed
    try {
      parsed = JSON.parse(encryptedData)
    } catch {
      throw new Error("Invalid Kyber encrypted data format")
    }
    
    if (!parsed.kyberCiphertext || !parsed.encrypted || !parsed.authTag) {
      throw new Error("Missing required Kyber data fields")
    }
    
    // Parse the private key
    const sk = Buffer.from(privateKey, 'hex')
    
    // Validate private key length for Kyber-768
    if (sk.length !== 2400) {
      throw new Error(`Invalid Kyber-768 private key length: ${sk.length}. Expected 2400 bytes`)
    }
    
    // Parse the ciphertext
    const ciphertext = Buffer.from(parsed.kyberCiphertext, 'hex')
    
    // Decapsulate using Kyber
    const sharedSecret = kyber.Decrypt768(ciphertext, sk)
    
    if (!sharedSecret || sharedSecret.length < 32) {
      throw new Error("Invalid shared secret from Kyber decapsulation")
    }
    
    // Use shared secret as AES-256-GCM key
    const aesKey = sharedSecret.slice(0, 32) // 256 bits
    const ivBuffer = Buffer.from(iv, 'hex')
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, ivBuffer)
    
    decipher.setAuthTag(Buffer.from(parsed.authTag, 'hex'))
    let decrypted = decipher.update(parsed.encrypted, 'hex', 'utf8')
    decrypted += decipher.final('utf8')
    
    return decrypted
  } catch (error) {
    console.error('Kyber decryption error:', error)
    throw new Error(`Kyber decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
  }
}

/**
 * Hybrid encryption combining AES and Kyber
 */
export async function encryptHybrid(data: string, aesKey: string, kyberPublicKey: string): Promise<{ encryptedData: string, iv: string, metadata: Record<string, any> }> {
  try {
    // Ensure Kyber public key is valid before proceeding
    if (!kyberPublicKey || typeof kyberPublicKey !== 'string' || Buffer.from(kyberPublicKey, 'hex').length !== 1184) {
      throw new Error(`Invalid Kyber public key passed to hybrid encryption. Got length: ${kyberPublicKey ? Buffer.from(kyberPublicKey, 'hex').length : 0}`);
    }
    // First encrypt with AES
    const aesResult = await encryptAES(data, aesKey)
    
    // Then encrypt the AES key with Kyber
    const kyberResult = await encryptKyber(aesKey, kyberPublicKey)
    
    // Combine both results
    const hybridData = JSON.stringify({
      aesEncrypted: aesResult.encryptedData,
      aesIv: aesResult.iv,
      kyberEncryptedKey: kyberResult.encryptedData,
      kyberIv: kyberResult.iv,
      algorithm: 'aes-256-gcm-hybrid'
    })
    
    return {
      encryptedData: hybridData,
      iv: aesResult.iv, // Use AES IV as primary IV
      metadata: {
        ...kyberResult.metadata,
        algorithm: 'aes-256-gcm-hybrid'
      }
    }
  } catch (error) {
    console.error('Hybrid encryption error:', error)
    throw new Error(`Hybrid encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
  }
}

/**
 * Hybrid decryption
 */
export async function decryptHybrid(encryptedData: string, iv: string, kyberPrivateKey: string): Promise<string> {
  try {
    // Parse the hybrid data
    let parsed
    try {
      parsed = JSON.parse(encryptedData)
    } catch {
      throw new Error("Invalid hybrid encrypted data format")
    }
    
    if (!parsed.kyberEncryptedKey || !parsed.aesEncrypted) {
      throw new Error("Missing required hybrid data fields")
    }
    
    // First decrypt the AES key with Kyber
    const aesKey = await decryptKyber(parsed.kyberEncryptedKey, parsed.kyberIv, kyberPrivateKey)
    
    // Then decrypt the data with AES
    return await decryptAES(parsed.aesEncrypted, parsed.aesIv, aesKey)
  } catch (error) {
    console.error('Hybrid decryption error:', error)
    throw new Error(`Hybrid decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
  }
}

/**
 * Main encryption function that routes to appropriate algorithm
 */
export async function encryptData(data: string, algorithm: EncryptionAlgorithm, keys: Record<string, string>): Promise<EncryptionResult> {
  try {
    switch (algorithm) {
      case 'aes-256-gcm':
        if (!keys.aesKey) {
          throw new Error("AES key required for aes-256-gcm encryption")
        }
        const aesResult = await encryptAES(data, keys.aesKey)
        return {
          encryptedData: aesResult.encryptedData,
          iv: aesResult.iv,
          algorithm: 'aes-256-gcm'
        }
        
      case 'kyber-768':
        if (!keys.kyberPublicKey) {
          throw new Error("Kyber public key required for kyber-768 encryption")
        }
        const kyberResult = await encryptKyber(data, keys.kyberPublicKey)
        return {
          encryptedData: kyberResult.encryptedData,
          iv: kyberResult.iv,
          algorithm: 'kyber-768',
          metadata: kyberResult.metadata
        }
        
      case 'aes-256-gcm-hybrid':
        if (!keys.aesKey || !keys.kyberPublicKey) {
          throw new Error("Both AES key and Kyber public key required for hybrid encryption")
        }
        const hybridResult = await encryptHybrid(data, keys.aesKey, keys.kyberPublicKey)
        return {
          encryptedData: hybridResult.encryptedData,
          iv: hybridResult.iv,
          algorithm: 'aes-256-gcm-hybrid',
          metadata: hybridResult.metadata
        }
        
      default:
        throw new Error(`Unsupported encryption algorithm: ${algorithm}`)
    }
  } catch (error) {
    console.error(`Encryption error for algorithm ${algorithm}:`, error)
    throw error
  }
}

/**
 * Main decryption function that routes to appropriate algorithm
 */
export async function decryptData(encryptedData: string, iv: string, algorithm: EncryptionAlgorithm, keys: Record<string, string>): Promise<DecryptionResult> {
  try {
    switch (algorithm) {
      case 'aes-256-gcm':
        if (!keys.aesKey) {
          throw new Error("AES key required for aes-256-gcm decryption")
        }
        const aesDecrypted = await decryptAES(encryptedData, iv, keys.aesKey)
        return {
          decryptedData: aesDecrypted,
          algorithm: 'aes-256-gcm'
        }
        
      case 'kyber-768':
        if (!keys.kyberPrivateKey) {
          throw new Error("Kyber private key required for kyber-768 decryption")
        }
        const kyberDecrypted = await decryptKyber(encryptedData, iv, keys.kyberPrivateKey)
        return {
          decryptedData: kyberDecrypted,
          algorithm: 'kyber-768'
        }
        
      case 'aes-256-gcm-hybrid':
        if (!keys.kyberPrivateKey) {
          throw new Error("Kyber private key required for hybrid decryption")
        }
        const hybridDecrypted = await decryptHybrid(encryptedData, iv, keys.kyberPrivateKey)
        return {
          decryptedData: hybridDecrypted,
          algorithm: 'aes-256-gcm-hybrid'
        }
        
      default:
        throw new Error(`Unsupported decryption algorithm: ${algorithm}`)
    }
  } catch (error) {
    console.error(`Decryption error for algorithm ${algorithm}:`, error)
    throw error
  }
}

/**
 * Enhanced key management with proper validation
 */
export async function upsertEncryptionKey(userId: string) {
  if (!userId) {
    throw new Error("User ID is required")
  }

  // Find existing active key
  const existingKey = await prisma.encryptionKey.findFirst({
    where: {
      active: true,
      userId: userId
    }
  })

  if (existingKey) {
    return existingKey
  }

  // Generate a new random encryption key
  const keyBuffer = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  )
  const exportedKey = await crypto.subtle.exportKey("raw", keyBuffer)
  const key = Buffer.from(exportedKey).toString('base64')

  // Create new active key
  return prisma.encryptionKey.create({
    data: {
      key: key,
      active: true,
      user: {
        connect: {
          id: userId
        }
      }
    }
  })
}

/**
 * Enhanced Kyber key management
 */
export async function upsertKyberKey(userId: string) {
  if (!userId) {
    throw new Error("User ID is required")
  }

  // Check for existing active Kyber key
  let activeKey = await prisma.kyberKey.findFirst({
    where: {
      userId: userId,
      active: true
    }
  })

  if (!activeKey) {
    try {
      // Generate new Kyber key pair
      const [publicKey, privateKey] = kyber.KeyGen768()
      
      // Validate key lengths
      if (publicKey.length !== 1184) {
        throw new Error(`Invalid public key length: ${publicKey.length}. Expected 1184 bytes`)
      }
      
      if (privateKey.length !== 2400) {
        throw new Error(`Invalid private key length: ${privateKey.length}. Expected 2400 bytes`)
      }
      
      // Deactivate all existing keys for this user
      await prisma.kyberKey.updateMany({
        where: {
          userId: userId,
          active: true
        },
        data: {
          active: false
        }
      })

      // Create new active key
      activeKey = await prisma.kyberKey.create({
        data: {
          userId: userId,
          publicKey: publicKey.toString('hex'),
          privateKey: privateKey.toString('hex'),
          active: true
        }
      })
    } catch (error) {
      console.error('Error generating Kyber key pair:', error)
      throw new Error(`Failed to generate Kyber key pair: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  } else {
    // Validate existing key
    try {
      const publicKeyBuffer = Buffer.from(activeKey.publicKey, 'hex')
      const privateKeyBuffer = Buffer.from(activeKey.privateKey, 'hex')
      
      if (publicKeyBuffer.length !== 1184) {
        console.warn('Invalid existing public key length, regenerating...')
        // Delete the invalid key and regenerate
        await prisma.kyberKey.delete({
          where: { id: activeKey.id }
        })
        return await upsertKyberKey(userId) // Recursive call to regenerate
      }
    } catch (error) {
      console.error('Error validating existing Kyber key:', error)
      // Delete the invalid key and regenerate
      await prisma.kyberKey.delete({
        where: { id: activeKey.id }
      })
      return await upsertKyberKey(userId) // Recursive call to regenerate
    }
  }

  return activeKey
}

/**
 * Validate encryption algorithm
 */
export async function validateEncryptionAlgorithm(algorithm: string): Promise<boolean> {
  return ['aes-256-gcm', 'kyber-768', 'aes-256-gcm-hybrid'].includes(algorithm)
}
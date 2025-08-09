import crypto from "node:crypto"

/**
 * Enhanced secure random generation
 */
export function generateSecureRandom(length: number): Buffer {
  return crypto.randomBytes(length)
}

/**
 * Generate a cryptographically secure salt
 */
export function generateSalt(length: number = 32): string {
  return crypto.randomBytes(length).toString('hex')
}

/**
 * Key derivation function using PBKDF2
 */
export function deriveKey(password: string, salt: string, iterations: number = 100000, keyLength: number = 32): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iterations, keyLength, 'sha256', (err, derivedKey) => {
      if (err) reject(err)
      else resolve(derivedKey)
    })
  })
}

/**
 * Enhanced password hashing with salt and iterations
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = generateSalt(32)
  const iterations = 100000
  const keyLength = 64
  
  const hash = await deriveKey(password, salt, iterations, keyLength)
  
  return JSON.stringify({
    salt,
    iterations,
    hash: hash.toString('hex')
  })
}

/**
 * Verify password against hash
 */
export async function verifyPassword(password: string, hashString: string): Promise<boolean> {
  try {
    const { salt, iterations, hash } = JSON.parse(hashString)
    const derivedHash = await deriveKey(password, salt, iterations, 64)
    return hash === derivedHash.toString('hex')
  } catch (error) {
    console.error('Password verification error:', error)
    return false
  }
}

/**
 * Generate a secure master key for user
 */
export async function generateMasterKey(userId: string, userPassword: string): Promise<string> {
  const salt = `user_${userId}_master`
  const iterations = 200000 // Higher iterations for master key
  const keyLength = 32
  
  const masterKey = await deriveKey(userPassword, salt, iterations, keyLength)
  return masterKey.toString('base64')
}

/**
 * Encrypt private keys with user's master key
 */
export async function encryptPrivateKey(privateKey: string, masterKey: string): Promise<{ encryptedKey: string, iv: string }> {
  const iv = generateSecureRandom(12)
  const keyBuffer = Buffer.from(masterKey, 'base64')
  
  const key = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt']
  )
  
  const encodedData = new TextEncoder().encode(privateKey)
  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    key,
    encodedData
  )
  
  return {
    encryptedKey: Buffer.from(encryptedBuffer).toString('base64'),
    iv: Buffer.from(iv).toString('base64')
  }
}

/**
 * Decrypt private keys with user's master key
 */
export async function decryptPrivateKey(encryptedKey: string, iv: string, masterKey: string): Promise<string> {
  const keyBuffer = Buffer.from(masterKey, 'base64')
  const ivBuffer = Buffer.from(iv, 'base64')
  const encryptedBuffer = Buffer.from(encryptedKey, 'base64')
  
  const key = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'AES-GCM', length: 256 },
    true,
    ['decrypt']
  )
  
  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: ivBuffer
    },
    key,
    encryptedBuffer
  )
  
  return new TextDecoder().decode(decryptedBuffer)
}

/**
 * Validate encryption strength
 */
export function validateEncryptionStrength(algorithm: string, keyLength?: number): boolean {
  const strongAlgorithms = ['aes-256-gcm', 'kyber-768', 'aes-256-gcm-hybrid']
  
  if (!strongAlgorithms.includes(algorithm)) {
    return false
  }
  
  if (algorithm === 'aes-256-gcm' && keyLength && keyLength < 256) {
    return false
  }
  
  return true
}

/**
 * Generate secure token with expiration
 */
export function generateSecureToken(payload: object, expiresIn: number = 24 * 60 * 60): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
  const content = Buffer.from(JSON.stringify({
    ...payload,
    exp: Math.floor(Date.now() / 1000) + expiresIn
  })).toString('base64url')
  
  const signature = crypto
    .createHmac('sha256', process.env.TOKEN_SECRET || 'secret')
    .update(`${header}.${content}`)
    .digest('base64url')
  
  return `${header}.${content}.${signature}`
}

/**
 * Verify secure token with expiration check
 */
export function verifySecureToken(token: string): { userId: string, email: string } | null {
  try {
    const [header, content, signature] = token.split('.')
    const expectedSignature = crypto
      .createHmac('sha256', process.env.TOKEN_SECRET || 'secret')
      .update(`${header}.${content}`)
      .digest('base64url')

    if (signature !== expectedSignature) {
      return null
    }

    const payload = JSON.parse(Buffer.from(content, 'base64url').toString())
    
    // Check expiration
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return null
    }

    return payload
  } catch {
    return null
  }
}

/**
 * Rate limiting helper
 */
export class RateLimiter {
  private attempts: Map<string, { count: number, resetTime: number }> = new Map()
  
  constructor(private maxAttempts: number = 5, private windowMs: number = 15 * 60 * 1000) {}
  
  isAllowed(identifier: string): boolean {
    const now = Date.now()
    const attempt = this.attempts.get(identifier)
    
    if (!attempt || now > attempt.resetTime) {
      this.attempts.set(identifier, { count: 1, resetTime: now + this.windowMs })
      return true
    }
    
    if (attempt.count >= this.maxAttempts) {
      return false
    }
    
    attempt.count++
    return true
  }
  
  reset(identifier: string): void {
    this.attempts.delete(identifier)
  }
}

/**
 * Security audit logging
 */
export function logSecurityEvent(event: string, userId?: string, details?: Record<string, any>): void {
  const logEntry = {
    timestamp: new Date().toISOString(),
    event,
    userId,
    details,
    ip: 'unknown', // In a real app, get from request
    userAgent: 'unknown' // In a real app, get from request
  }
  
  console.log('SECURITY_EVENT:', JSON.stringify(logEntry))
  // In production, send to security monitoring service
}

/**
 * Validate input for security
 */
export function validateSecureInput(input: string, maxLength: number = 1000): boolean {
  if (!input || typeof input !== 'string') {
    return false
  }
  
  if (input.length > maxLength) {
    return false
  }
  
  // Check for potentially dangerous patterns
  const dangerousPatterns = [
    /<script/i,
    /javascript:/i,
    /data:text\/html/i,
    /vbscript:/i,
    /on\w+\s*=/i
  ]
  
  return !dangerousPatterns.some(pattern => pattern.test(input))
}

/**
 * Sanitize input for safe storage
 */
export function sanitizeInput(input: string): string {
  return input
    .replace(/[<>]/g, '') // Remove angle brackets
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+\s*=/gi, '') // Remove event handlers
    .trim()
}

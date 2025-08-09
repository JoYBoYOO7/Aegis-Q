import crypto from "node:crypto"

const SALT_LENGTH = 16
const KEY_LENGTH = 64
const TOKEN_SECRET = process.env.TOKEN_SECRET || "secret"

/**
 * Enhanced password hashing using PBKDF2
 */
export async function hashPassword(password: string): Promise<string> {
  if (!validateUserInput(password)) {
    throw new Error("Invalid password input")
  }
  
  try {
    const salt = crypto.randomBytes(32).toString('hex')
    const iterations = 100000
    const keyLength = 64
    
    const hash = await new Promise<Buffer>((resolve, reject) => {
      crypto.pbkdf2(password, salt, iterations, keyLength, 'sha256', (err, derivedKey) => {
        if (err) reject(err)
        else resolve(derivedKey)
      })
    })
    
    return JSON.stringify({
      salt,
      iterations,
      hash: hash.toString('hex')
    })
  } catch (error) {
    logSecurityEvent("password_hash_failed", undefined, { error: error instanceof Error ? error.message : 'Unknown error' })
    throw error
  }
}

/**
 * Enhanced password verification with backward compatibility
 */
export async function verifyPassword(password: string, hashString: string): Promise<boolean> {
  if (!validateUserInput(password)) {
    return false
  }
  
  try {
    // Try to parse as JSON (new format)
    try {
      const { salt, iterations, hash } = JSON.parse(hashString)
      const derivedHash = await new Promise<Buffer>((resolve, reject) => {
        crypto.pbkdf2(password, salt, iterations, 64, 'sha256', (err, derivedKey) => {
          if (err) reject(err)
          else resolve(derivedKey)
        })
      })
      return hash === derivedHash.toString('hex')
    } catch (jsonError) {
      // If JSON parsing fails, try old format (salt:hash)
      const [salt, hash] = hashString.split(':')
      if (!salt || !hash) {
        return false
      }
      
      const derivedHash = await new Promise<Buffer>((resolve, reject) => {
        crypto.scrypt(password, salt, 64, (err, derivedKey) => {
          if (err) reject(err)
          else resolve(derivedKey)
        })
      })
      return hash === derivedHash.toString('hex')
    }
  } catch (error) {
    logSecurityEvent("password_verification_failed", undefined, { error: error instanceof Error ? error.message : 'Unknown error' })
    return false
  }
}

/**
 * Generate secure token with expiration
 */
export function generateToken(payload: object): string {
  try {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
    const content = Buffer.from(JSON.stringify({
      ...payload,
      exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60
    })).toString('base64url')
    
    const signature = crypto
      .createHmac('sha256', TOKEN_SECRET)
      .update(`${header}.${content}`)
      .digest('base64url')
    
    return `${header}.${content}.${signature}`
  } catch (error) {
    logSecurityEvent("token_generation_failed", undefined, { error: error instanceof Error ? error.message : 'Unknown error' })
    throw error
  }
}

/**
 * Verify secure token with expiration check
 */
export function verifyToken(token: string): { userId: string, email: string } | null {
  try {
    const [header, content, signature] = token.split('.')
    const expectedSignature = crypto
      .createHmac('sha256', TOKEN_SECRET)
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
  } catch (error) {
    logSecurityEvent("token_verification_failed", undefined, { error: error instanceof Error ? error.message : 'Unknown error' })
    return null
  }
}

/**
 * Sanitize user input
 */
export function sanitizeUserInput(input: string): string {
  return input
    .replace(/[<>]/g, '') // Remove angle brackets
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+\s*=/gi, '') // Remove event handlers
    .trim()
}

/**
 * Validate user input
 */
export function validateUserInput(input: string, maxLength: number = 1000): boolean {
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
 * Security audit logging
 */
function logSecurityEvent(event: string, userId?: string, details?: Record<string, any>): void {
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

export type DecryptedPassword = {
  id: string;
  service: string;
  username: string;
  password: string;
  algorithm: string;
  createdAt: Date;
  updatedAt: Date;
}
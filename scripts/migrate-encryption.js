const { PrismaClient } = require('@prisma/client')

const prisma = new PrismaClient()

async function migrateEncryption() {
  console.log('Starting encryption migration...')

  try {
    // Update algorithm names to new format
    console.log('Updating algorithm names...')
    await prisma.password.updateMany({
      where: {
        algorithm: 'aes'
      },
      data: {
        algorithm: 'aes-256-gcm'
      }
    })

    await prisma.password.updateMany({
      where: {
        algorithm: 'pq'
      },
      data: {
        algorithm: 'kyber-768'
      }
    })

    console.log('Database schema updated successfully')

    // Clean up any corrupted data - check if fields exist first
    console.log('Cleaning up corrupted data...')
    
    try {
      const corruptedPasswords = await prisma.password.findMany({
        where: {
          OR: [
            { encryptedData: null },
            { encryptedData: '' },
            { iv: null },
            { iv: '' }
          ]
        }
      })

      if (corruptedPasswords.length > 0) {
        console.log(`Found ${corruptedPasswords.length} corrupted passwords, removing...`)
        await prisma.password.deleteMany({
          where: {
            id: {
              in: corruptedPasswords.map(p => p.id)
            }
          }
        })
      }
    } catch (error) {
      console.log('Skipping corrupted data cleanup - schema may not be updated yet')
    }

    // Validate encryption keys
    console.log('Validating encryption keys...')
    try {
      const invalidKeys = await prisma.encryptionKey.findMany({
        where: {
          OR: [
            { key: null },
            { key: '' },
            { active: null }
          ]
        }
      })

      if (invalidKeys.length > 0) {
        console.log(`Found ${invalidKeys.length} invalid encryption keys, removing...`)
        await prisma.encryptionKey.deleteMany({
          where: {
            id: {
              in: invalidKeys.map(k => k.id)
            }
          }
        })
      }
    } catch (error) {
      console.log('Skipping encryption key validation - schema may not be updated yet')
    }

    // Validate Kyber keys
    console.log('Validating Kyber keys...')
    try {
      const invalidKyberKeys = await prisma.kyberKey.findMany({
        where: {
          OR: [
            { publicKey: null },
            { publicKey: '' },
            { privateKey: null },
            { privateKey: '' },
            { active: null }
          ]
        }
      })

      if (invalidKyberKeys.length > 0) {
        console.log(`Found ${invalidKyberKeys.length} invalid Kyber keys, removing...`)
        await prisma.kyberKey.deleteMany({
          where: {
            id: {
              in: invalidKyberKeys.map(k => k.id)
            }
          }
        })
      }
    } catch (error) {
      console.log('Skipping Kyber key validation - schema may not be updated yet')
    }

    console.log('Migration completed successfully!')
  } catch (error) {
    console.error('Migration failed:', error)
    throw error
  } finally {
    await prisma.$disconnect()
  }
}

// Run migration if this script is executed directly
if (require.main === module) {
  migrateEncryption()
    .then(() => {
      console.log('Migration script completed')
      process.exit(0)
    })
    .catch((error) => {
      console.error('Migration script failed:', error)
      process.exit(1)
    })
}

module.exports = { migrateEncryption }

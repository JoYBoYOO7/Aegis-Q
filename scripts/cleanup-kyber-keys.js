const { PrismaClient } = require('@prisma/client')

const prisma = new PrismaClient()

async function cleanupKyberKeys() {
  console.log('Cleaning up invalid Kyber keys...')

  try {
    // Find all Kyber keys
    const allKeys = await prisma.kyberKey.findMany()
    console.log(`Found ${allKeys.length} Kyber keys`)

    let deletedCount = 0
    let validCount = 0

    for (const key of allKeys) {
      try {
        const publicKeyBuffer = Buffer.from(key.publicKey, 'hex')
        const privateKeyBuffer = Buffer.from(key.privateKey, 'hex')
        
        console.log(`Key ${key.id}: Public key length: ${publicKeyBuffer.length}, Private key length: ${privateKeyBuffer.length}`)
        
        if (publicKeyBuffer.length !== 1184 || privateKeyBuffer.length !== 2400) {
          console.log(`Deleting invalid key ${key.id}...`)
          await prisma.kyberKey.delete({
            where: { id: key.id }
          })
          deletedCount++
        } else {
          validCount++
        }
      } catch (error) {
        console.log(`Deleting corrupted key ${key.id}...`)
        await prisma.kyberKey.delete({
          where: { id: key.id }
        })
        deletedCount++
      }
    }

    console.log(`Cleanup completed: ${validCount} valid keys, ${deletedCount} invalid keys deleted`)
  } catch (error) {
    console.error('Cleanup failed:', error)
    throw error
  } finally {
    await prisma.$disconnect()
  }
}

// Run cleanup if this script is executed directly
if (require.main === module) {
  cleanupKyberKeys()
    .then(() => {
      console.log('Cleanup script completed')
      process.exit(0)
    })
    .catch((error) => {
      console.error('Cleanup script failed:', error)
      process.exit(1)
    })
}

module.exports = { cleanupKyberKeys }

const kyber = require('crystals-kyber');

console.log('Testing Kyber library...');

try {
  // Test key generation
  console.log('Generating Kyber key pair...');
  const [publicKey, privateKey] = kyber.KeyGen768();
  
  console.log('Public key type:', typeof publicKey);
  console.log('Public key length:', publicKey.length);
  console.log('Public key first 10 bytes:', publicKey.slice(0, 10));
  
  console.log('Private key type:', typeof privateKey);
  console.log('Private key length:', privateKey.length);
  console.log('Private key first 10 bytes:', privateKey.slice(0, 10));
  
  // Test encryption
  console.log('\nTesting encryption...');
  const testData = 'Hello, Kyber!';
  const [ciphertext, sharedSecret] = kyber.Encrypt768(publicKey);
  
  console.log('Ciphertext length:', ciphertext.length);
  console.log('Shared secret length:', sharedSecret.length);
  
  // Test decryption
  console.log('\nTesting decryption...');
  const decryptedSecret = kyber.Decrypt768(ciphertext, privateKey);
  
  console.log('Decrypted secret length:', decryptedSecret.length);
  console.log('Secrets match:', Buffer.compare(sharedSecret, decryptedSecret) === 0);
  
  console.log('\nKyber test completed successfully!');
} catch (error) {
  console.error('Kyber test failed:', error);
  process.exit(1);
}

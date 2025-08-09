
# SecureVault 🔐

SecureVault is a secure file encryption and decryption web application built with Next.js. It utilizes AES-256 encryption to protect your files in the browser, ensuring your data remains private. **Note:** SecureVault is not post-quantum secure.

---

## ⚠️ Caution

> ⚠️ Current build is **not** resistant to post-quantum attacks. Do not use for highly sensitive data requiring post-quantum security.

---

## Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) (version 18 or higher)
- [npm](https://www.npmjs.com/) (comes with Node.js)
- [yarn](https://yarnpkg.com/) (optional)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/securevault.git
   cd securevault
   ```
2. Install dependencies:
   ```bash
   npm install
   # or
   yarn install
   ```

### Running the Development Server
```bash
npm run dev
# or
yarn dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser to use SecureVault.

---

## Features
- AES-256 encryption and decryption for files
- File upload & download
- Secure key generation
- Responsive, modern user interface
- All encryption/decryption happens locally in your browser (no files or keys are sent to a server)

---

## Usage
### Encrypting a File
1. Open SecureVault in your browser.
2. Click **Upload File** and select the file you wish to encrypt.
3. Generate a secure encryption key or enter your own.
4. Click **Encrypt**.
5. Download the encrypted file and securely save the encryption key.

### Decrypting a File
1. Open SecureVault in your browser.
2. Click **Upload File** and select the encrypted file.
3. Enter the encryption key used during encryption.
4. Click **Decrypt**.
5. Download the decrypted file.

---

## Learn More

SecureVault is built with [Next.js](https://nextjs.org/) for the frontend and uses the [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) algorithm for secure encryption and decryption, all handled locally in the browser for maximum privacy.

---

## Deploy

The easiest way to deploy SecureVault is with [Vercel](https://vercel.com/new). For more details, see the [Vercel deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying).


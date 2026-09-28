import crypto from 'crypto';
import bcrypt from 'bcryptjs';

const MASTER_KEY = process.env.ENCRYPTION_MASTER_KEY || '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

export async function hashPassword(password: string): Promise<string> {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
}

export async function comparePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

/**
 * AES-256-GCM symmetric encryption for protecting sensitive enterprise resource payloads
 */
export function encryptData(plainText: string): string {
  const key = Buffer.from(MASTER_KEY.slice(0, 64), 'hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');

  // Format: iv:tag:encrypted
  return `${iv.toString('hex')}:${tag}:${encrypted}`;
}

export function decryptData(cipherTextWithMeta: string): string {
  try {
    const parts = cipherTextWithMeta.split(':');
    if (parts.length !== 3) return cipherTextWithMeta; // If unencrypted raw payload
    
    const [ivHex, tagHex, encryptedHex] = parts;
    const key = Buffer.from(MASTER_KEY.slice(0, 64), 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);

    let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch {
    return '[Decryption Error: Invalid Key or Tampered Payload]';
  }
}

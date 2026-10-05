const crypto = require('crypto');
const { promisify } = require('util');

const scrypt = promisify(crypto.scrypt);
const KEY_LENGTH = 64;

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('base64url');
  const derivedKey = await scrypt(password, salt, KEY_LENGTH);
  return `scrypt$${salt}$${Buffer.from(derivedKey).toString('base64url')}`;
}

async function verifyPassword(password, storedHash) {
  if (typeof storedHash !== 'string') return false;
  const [algorithm, salt, encodedKey, extra] = storedHash.split('$');
  if (algorithm !== 'scrypt' || !salt || !encodedKey || extra) return false;

  try {
    const expected = Buffer.from(encodedKey, 'base64url');
    const actual = Buffer.from(await scrypt(password, salt, expected.length));
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

module.exports = { hashPassword, verifyPassword };

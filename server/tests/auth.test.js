const assert = require('assert');
const http = require('http');

process.env.AUTH_USERNAME = process.env.AUTH_USERNAME || 'member3-test';
process.env.AUTH_PASSWORD = process.env.AUTH_PASSWORD || 'test-password-only';
process.env.AUTH_SECRET = process.env.AUTH_SECRET || 'member3-test-secret-that-is-at-least-32-characters';

const app = require('../src/app');
const { issueToken, verifyToken } = require('../src/security/auth');
const { hashPassword, verifyPassword } = require('../src/security/passwords');

function request(server, { method, path, body, token }) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const headers = {};
    if (data) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(data);
    }
    if (token) headers.Authorization = `Bearer ${token}`;

    const req = http.request({
      hostname: '127.0.0.1',
      port: server.address().port,
      path,
      method,
      headers
    }, res => {
      let responseBody = '';
      res.on('data', chunk => { responseBody += chunk; });
      res.on('end', () => resolve({
        statusCode: res.statusCode,
        body: responseBody ? JSON.parse(responseBody) : null
      }));
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function testAuth() {
  console.log('--- Running Authentication Tests ---');
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));

  try {
    const passwordHash = await hashPassword('StrongPassword123');
    assert(passwordHash.startsWith('scrypt$'));
    assert.strictEqual(await verifyPassword('StrongPassword123', passwordHash), true);
    assert.strictEqual(await verifyPassword('wrong-password', passwordHash), false);
    console.log('  [PASS] Account passwords are salted, hashed, and safely verified');

    const invalidSignup = await request(server, {
      method: 'POST',
      path: '/api/auth/signup',
      body: {
        displayName: 'Test User',
        username: 'test-user',
        email: 'test@example.com',
        password: 'weak'
      }
    });
    assert.strictEqual(invalidSignup.statusCode, 400);
    console.log('  [PASS] Sign-up rejects weak account credentials');

    const originalMongoUri = process.env.MONGODB_URI;
    delete process.env.MONGODB_URI;
    const unavailableSignup = await request(server, {
      method: 'POST',
      path: '/api/auth/signup',
      body: {
        displayName: 'Test User',
        username: 'test-user',
        email: 'test@example.com',
        password: 'StrongPassword123'
      }
    });
    if (originalMongoUri === undefined) delete process.env.MONGODB_URI;
    else process.env.MONGODB_URI = originalMongoUri;
    assert.strictEqual(unavailableSignup.statusCode, 503);
    console.log('  [PASS] Sign-up validates correctly and fails safely without MongoDB');

    const rejected = await request(server, {
      method: 'POST',
      path: '/api/auth/login',
      body: { username: 'member3-test', password: 'wrong-password' }
    });
    assert.strictEqual(rejected.statusCode, 401);
    console.log('  [PASS] Invalid credentials are rejected');

    const accepted = await request(server, {
      method: 'POST',
      path: '/api/auth/login',
      body: { username: 'member3-test', password: 'test-password-only' }
    });
    assert.strictEqual(accepted.statusCode, 200);
    assert(accepted.body.token);
    assert.strictEqual(accepted.body.user.username, 'member3-test');
    console.log('  [PASS] Valid credentials create a signed session');

    const claims = verifyToken(accepted.body.token);
    assert.strictEqual(claims.sub, 'member3-test');
    assert.strictEqual(verifyToken(`${accepted.body.token}tampered`), null);
    console.log('  [PASS] Session signatures reject tampering');

    const session = await request(server, {
      method: 'GET',
      path: '/api/auth/session',
      token: accepted.body.token
    });
    assert.strictEqual(session.statusCode, 200);
    assert.strictEqual(session.body.authenticated, true);

    const protectedRequest = await request(server, {
      method: 'POST',
      path: '/api/scan',
      body: {}
    });
    assert.strictEqual(protectedRequest.statusCode, 401);

    const token = issueToken('member3-test').token;
    assert(token);
    console.log('  [PASS] Protected APIs require a valid bearer session');
  } finally {
    server.close();
  }

  return true;
}

if (require.main === module) {
  testAuth().catch(error => {
    console.error('Authentication test failed:', error);
    process.exit(1);
  });
}

module.exports = { testAuth };

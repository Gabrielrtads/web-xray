import test from 'node:test';
import assert from 'node:assert/strict';
import { redactUrl, sanitizeHeaders, scrubSensitiveData, ALLOWED_HEADERS } from './autopsia_engine.mjs';

test('🛡️ redactUrl deve mascarar query parameters e credenciais embutidas', () => {
  // 1. URL com query parameters sensíveis
  const url1 = 'https://app.com/api/v1/user?token=secret123&client_id=456';
  const clean1 = redactUrl(url1);
  assert.equal(clean1, 'https://app.com/api/v1/user?token=%5BREDACTED%5D&client_id=%5BREDACTED%5D');

  // 2. URL com credenciais embutidas (user:pass@host)
  const url2 = 'https://admin:SuperSecret123@api.internal.com/data';
  const clean2 = redactUrl(url2);
  assert.equal(clean2.includes('SuperSecret123'), false, 'Senha embutida não pode vazar');
  assert.equal(clean2.includes('REDACTED'), true, 'Username deve ser mascarado');

  // 3. URL com fragmento OAuth (#access_token=...)
  const url3 = 'https://app.com/callback#access_token=xyz987&token_type=bearer';
  const clean3 = redactUrl(url3);
  assert.equal(clean3.includes('xyz987'), false, 'Token no hash não pode vazar');
  assert.equal(decodeURIComponent(clean3).includes('[REDACTED]'), true);

  // 4. URL relativa
  const url4 = '/api/v2/reports?date=2026-10-22&key=api123';
  const clean4 = redactUrl(url4);
  assert.equal(clean4.includes('api123'), false, 'Key em query relativa não pode vazar');
  assert.equal(decodeURIComponent(clean4).includes('[REDACTED]'), true);
});

test('🛡️ sanitizeHeaders deve impor Allowlist estrita e censurar headers de autenticação', () => {
  const dirtyHeaders = {
    'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    'Cookie': 'session_id=s3cr3t; remember=true',
    'Set-Cookie': 'token=abc',
    'X-Api-Key': 'key-9999',
    'X-Custom-Tenant-Secret': 'secret_tenant_1',
    'Content-Type': 'application/json',
    'Host': 'api.barber.fi',
    'User-Agent': 'Mozilla/5.0'
  };

  const safe = sanitizeHeaders(dirtyHeaders);

  // Campos seguros permitidos
  assert.equal(safe['content-type'], 'application/json');
  assert.equal(safe['host'], 'api.barber.fi');
  assert.equal(safe['user-agent'], 'Mozilla/5.0');

  // Headers sensíveis e customizados devem ser censurados
  assert.equal(safe['authorization'], '[REDACTED_CUSTOM_HEADER]');
  assert.equal(safe['cookie'], '[REDACTED_CUSTOM_HEADER]');
  assert.equal(safe['set-cookie'], '[REDACTED_CUSTOM_HEADER]');
  assert.equal(safe['x-api-key'], '[REDACTED_CUSTOM_HEADER]');
  assert.equal(safe['x-custom-tenant-secret'], '[REDACTED_CUSTOM_HEADER]');
});

test('🛡️ scrubSensitiveData deve mascarar JWTs, API Keys, Tokens e Emails', () => {
  const rawText = 'Erro ao processar token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDN secretly for user admin@empresa.com com chave sk-12345678901234567890';
  const scrubbed = scrubSensitiveData(rawText);

  assert.equal(scrubbed.includes('eyJ'), false, 'JWT não pode sobreviver');
  assert.equal(scrubbed.includes('[REDACTED_JWT]'), true);
  assert.equal(scrubbed.includes('admin@empresa.com'), false, 'Email não pode vazar');
  assert.equal(scrubbed.includes('[REDACTED_EMAIL]'), true);
  assert.equal(scrubbed.includes('sk-12345'), false, 'API Key não pode vazar');
  assert.equal(scrubbed.includes('[REDACTED_KEY]'), true);
});

test('🛡️ Objeto aninhado com chaves sensíveis deve ser mascarado', () => {
  const obj = {
    user: 'gabriel',
    auth_token: 'secret_token_abc',
    preferences: {
      theme: 'dark',
      apiKey: 'sk-99999999999999999999'
    }
  };

  const scrubbed = scrubSensitiveData(obj);
  assert.equal(scrubbed.auth_token, '[REDACTED_SECRET]');
  assert.equal(scrubbed.preferences.apiKey, '[REDACTED_SECRET]');
  assert.equal(scrubbed.preferences.theme, 'dark');
});

test('🛡️ Auditoria de Web Storage nunca deve conter propriedade "value"', () => {
  // Simulando a lógica de auditoria de storage do engine
  function simulateStorageAudit(mockStorage) {
    const keys = [];
    for (let i = 0; i < mockStorage.length; i++) {
      const k = mockStorage.key(i);
      const val = mockStorage.getItem(k) || '';
      let inferredType = 'string';
      try {
        const p = JSON.parse(val);
        inferredType = typeof p === 'object' ? (Array.isArray(p) ? 'array' : 'object') : typeof p;
      } catch {}
      keys.push({
        key: scrubSensitiveData(k),
        sizeBytes: val.length,
        type: inferredType,
        isSensitiveName: /(token|auth|key|secret|jwt|session|cred|pass|cpf|card)/i.test(k)
      });
    }
    return keys;
  }

  const mock = {
    length: 2,
    key: (i) => (i === 0 ? 'userProfile' : 'authToken'),
    getItem: (k) => (k === 'userProfile' ? '{"name":"Gabriel","email":"gabriel@empresa.com"}' : 'jwt_secret_xyz')
  };

  const audited = simulateStorageAudit(mock);
  assert.equal(audited.length, 2);
  
  for (const item of audited) {
    assert.equal('value' in item, false, 'Propriedade "value" NUNCA deve existir em chaves de storage');
    assert.ok(typeof item.sizeBytes === 'number');
    assert.ok(typeof item.type === 'string');
  }
});

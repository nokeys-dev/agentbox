import { request } from 'node:http';
import { SIGNATURE_HEADER, TIMESTAMP_HEADER, signAdminRequest } from './admin-auth.js';

// `adminSecret`, when given, signs the request (see admin-auth.js). Only approval-web holds it;
// the host CLI never does, so agentd rejects any `oidc:` reviewer the CLI submits.
export function adminRequest(socketPath, method, path, body, { adminSecret, now = Date.now } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const headers = payload ? { 'content-type': 'application/json', 'content-length': payload.length } : {};
    if (adminSecret) {
      const timestamp = String(now());
      headers[TIMESTAMP_HEADER] = timestamp;
      headers[SIGNATURE_HEADER] = signAdminRequest(adminSecret, { method, path, body: payload ? payload.toString('utf8') : '', timestamp });
    }
    const req = request({ socketPath, method, path, timeout: 5000, headers }, async (response) => {
      try {
        const chunks = [];
        for await (const chunk of response) chunks.push(chunk);
        const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (response.statusCode !== 200) throw Object.assign(new Error(value.message), { code: value.code, status: response.statusCode });
        resolve(value);
      } catch (error) { reject(error); }
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('Admin socket timed out')));
    req.end(payload);
  });
}

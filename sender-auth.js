import { verifyDkim } from './dkim-verify.js';

const address = value => typeof value === 'string' && value.length <= 254
  && /^[^\s@<>]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(value.trim())
  ? value.trim().toLowerCase() : null;

// DKIM uses public DNS TXT keys. HTTPS DNS avoids unsupported native DNS in Workers.
export function createTxtResolver(send = (...args) => fetch(...args)) {
  const started = Date.now();
  let lookups = 0;
  return async (name, type) => {
    if (type !== 'TXT' || ++lookups > 8 || Date.now() - started >= 10000) {
      throw Object.assign(new Error('DNS lookup budget exceeded'), { code: 'ETIMEOUT' });
    }
    const url = new URL('https://cloudflare-dns.com/dns-query');
    url.searchParams.set('name', name);
    url.searchParams.set('type', 'TXT');
    const response = await send(url.href, {
      headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(Math.min(5000, 10000 - (Date.now() - started))),
    });
    if (!response.ok) throw Object.assign(new Error('DNS lookup failed'), { code: 'ETIMEOUT' });
    const data = await response.json();
    if (data.Status !== 0) throw Object.assign(new Error('DNS lookup failed'), { code: data.Status === 3 ? 'ENOTFOUND' : 'ETIMEOUT' });
    const records = (data.Answer || []).filter(answer => answer.type === 16).map(answer => {
      if (typeof answer.data !== 'string') return [];
      return [...answer.data.matchAll(/"((?:\\.|[^"\\])*)"/g)].map(match => match[1]
        .replace(/\\(\d{3})/g, (_all, digits) => String.fromCharCode(Number(digits))).replace(/\\([\\"])/g, '$1'));
    });
    if (!records.length) throw Object.assign(new Error('DKIM key missing'), { code: 'ENOTFOUND' });
    // RFC 6376 keys must be unambiguous: never pick the first of multiple records.
    if (records.length !== 1) throw Object.assign(new Error('Ambiguous DKIM key'), { code: 'EINVALIDVAL' });
    return records;
  };
}

export async function authenticateSender(raw, parsed, envelopeSender, { resolver = createTxtResolver() } = {}) {
  const from = address(parsed.from?.address);
  const envelope = address(envelopeSender);
  if (!from || !envelope) return { ok: false, reason: 'sender_invalid', senderAuthenticated: false };
  if (from !== envelope) return { ok: false, reason: 'sender_mismatch', senderAuthenticated: false };
  const signatures = parsed.headers?.filter(header => header.key.toLowerCase() === 'dkim-signature') || [];
  if (!signatures.length) return { ok: false, reason: 'sender_unsigned', senderAuthenticated: false };
  if (signatures.length > 8) return { ok: false, reason: 'sender_auth_too_complex', senderAuthenticated: false };
  let verified;
  try {
    verified = await verifyDkim(raw, { resolver, sender: envelope, strict: true, minBitLength: 1024 });
  } catch {
    return { ok: false, reason: 'sender_auth_unavailable', senderAuthenticated: false };
  }
  // Bind the verified single From mailbox to the same address PostalMime parsed.
  if (verified.fromFields !== 1 || verified.fromSyntax !== 'valid' || verified.headerFrom?.length !== 1
    || address(verified.headerFrom[0]) !== from) {
    return { ok: false, reason: 'sender_invalid', senderAuthenticated: false };
  }
  const domain = from.split('@')[1];
  const aligned = verified.results.filter(result => result.signingDomain?.toLowerCase() === domain);
  const accepted = aligned.find(result => result.status?.result === 'pass' && !result.status.testing
    && result.canonBodyLengthLimited === false && typeof result.signingHeaders?.keys === 'string'
    && result.signingHeaders.keys.split(':').some(key => key.trim().toLowerCase() === 'from'));
  if (accepted) return { ok: true, sender: from, senderAuthenticated: true, dkimResult: 'pass', dkimDomain: domain };
  const temporary = aligned.some(result => result.status?.result === 'temperror');
  return { ok: false, senderAuthenticated: false, dkimResult: temporary ? 'temperror' : 'fail',
    reason: temporary ? 'sender_auth_unavailable' : 'sender_signature_invalid' };
}

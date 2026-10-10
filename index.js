import PostalMime from 'postal-mime';
import { authenticateSender } from './sender-auth.js';

export function createEmailHandler({ parse = raw => PostalMime.parse(raw), send = (...args) => fetch(...args), authenticate = authenticateSender } = {}) {
  return async function email(message, env) {
    const diagnostics = {
      eventId: crypto.randomUUID(), envelopeSender: message.from,
      recipient: message.to, rawBytes: message.rawSize,
    };
    let stage = 'configuration';
    let eventsUrl;
    const report = async (eventStage, reason, backendStatus) => {
      if (!eventsUrl) return;
      try {
        const response = await send(eventsUrl, {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Worker-Secret': env.WORKER_SECRET_KEY },
          body: JSON.stringify({ ...diagnostics, stage: eventStage, reason, backendStatus }),
          signal: AbortSignal.timeout(5000),
        });
        if (!response.ok) console.error('Worker diagnostics rejected', response.status, diagnostics.eventId);
      } catch {
        // Reporting must not prevent verification or hide the original failure.
        console.error('Worker diagnostics unavailable', diagnostics.eventId);
      }
    };
    try {
      const verifyUrl = new URL(env.BACKEND_VERIFY_URL);
      if (verifyUrl.protocol !== 'https:' || !env.WORKER_SECRET_KEY) throw new Error('Invalid configuration');
      eventsUrl = new URL('/api/auth/worker-events', verifyUrl).href;
      if (message.rawSize > 1024 * 1024) {
        await report('rejected', 'oversized_email');
        message.setReject('Verification email is too large. Send a new message containing your code.');
        return;
      }
      stage = 'parse';
      const raw = await new Response(message.raw).arrayBuffer();
      if (raw.byteLength > 1024 * 1024) {
        await report('rejected', 'oversized_email');
        message.setReject('Verification email is too large. Send a new message containing your code.');
        return;
      }
      const parsed = await parse(raw);
      const emailText = parsed.text || '';
      Object.assign(diagnostics, {
        headerFrom: parsed.from?.address, forwardedSender: message.from,
        textBytes: new TextEncoder().encode(emailText).byteLength,
        hasText: Boolean(emailText.trim()), hasHtml: Boolean(parsed.html),
      });
      await report('received');
      if (!diagnostics.hasText || diagnostics.textBytes > 16 * 1024) {
        await report('rejected', diagnostics.hasText ? 'oversized_body' : 'empty_body');
        message.setReject('Missing or oversized verification text. Send a new plain-text message containing your code.');
        return;
      }
      stage = 'authentication';
      const authentication = await authenticate(raw, parsed, message.from);
      Object.assign(diagnostics, {
        senderAuthenticated: authentication.senderAuthenticated,
        dkimResult: authentication.dkimResult, dkimDomain: authentication.dkimDomain,
      });
      if (!authentication.ok) {
        await report('rejected', authentication.reason);
        message.setReject(authentication.reason === 'sender_auth_unavailable'
          ? 'Sender verification is temporarily unavailable. Please try again shortly.'
          : 'We could not verify your sender address. Send a new email directly from your registered address using Gmail, Outlook, or a standard mail client connected to your email provider. Do not forward the email or use a different From address. Custom domains must sign outgoing mail with DKIM for the From domain.');
        return;
      }
      diagnostics.forwardedSender = authentication.sender;
      stage = 'network';
      const response = await send(verifyUrl.href, {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Worker-Secret': env.WORKER_SECRET_KEY },
        body: JSON.stringify({ text: emailText, sender: authentication.sender, diagnostics: { ...diagnostics, stage: 'forwarding' } }),
        signal: AbortSignal.timeout(15000),
      });
      const details = await response.json().catch(() => ({}));
      if (!response.ok) {
        await report('rejected', details.reason || 'backend_rejected', response.status);
        message.setReject(response.status === 400
          ? 'Verification failed. Request a new code and send it from the registered email address.'
          : 'Verification could not be processed. Please try again later.');
        return;
      }
      if (details.verified !== true) {
        await report('failed', 'backend_invalid_response', response.status);
        message.setReject('Verification server returned an unexpected response. Please try again later.');
        return;
      }
      await report('verified', 'verified', response.status);
      console.log('Email verified', diagnostics.eventId);
    } catch {
      const reason = stage === 'parse' ? 'parse_error' : stage === 'authentication' ? 'sender_auth_unavailable'
        : stage === 'network' ? 'network_error' : 'configuration_error';
      await report('failed', reason);
      console.error('Email processing failed', reason, diagnostics.eventId);
      message.setReject('Internal routing error. Please try again later.');
    }
  };
}

export default { email: createEmailHandler() };

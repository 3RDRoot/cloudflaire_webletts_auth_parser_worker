import PostalMime from 'postal-mime';

export default {
  async email(message, env, ctx) {
    try {
      // 1. Parse the raw incoming email stream using postal-mime
      const rawEmail = await readStreamToBuffer(message.raw);
      const parser = new PostalMime();
      const emailParsed = await parser.parse(rawEmail);

      const senderEmail = message.from;
      const emailText = emailParsed.text || '';

      // 2. check mail size 16bytes
      if (!emailText.trim() || new TextEncoder().encode(emailText).byteLength > 16 * 1024) {
        message.setReject('Missing or oversized verification email body. Please Start new empty message and send.');
        return;
      }

      // 3. send to server
      const backendResponse = await fetch(env.BACKEND_VERIFY_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Worker-Secret': env.WORKER_SECRET_KEY, // Protect your backend endpoint
        },
        body: JSON.stringify({
          text: emailText,
          sender: senderEmail,
        }),
      });


    // 4. if error send error email reject to sender with reason
     if (!backendResponse.ok) {
        const reason = backendResponse.status === 400
          ? 'Verification code is invalid or expired. Request a new code and resend it.'
          : 'Verification could not be processed. Please try again later.';
      
        message.setReject(reason);
        return;
      }

      console.log(`Successfully authenticated token for sender: ${senderEmail}`);
    } catch (err) {
      console.error("Error processing inbound email:", err);
      console.error(
        "Backend verification failed:",
        backendResponse.status,
        await backendResponse.text()
      );
      message.setReject("Internal routing error.");
    }
  }
};

// Helper utility to convert the EmailMessage stream to an ArrayBuffer
async function readStreamToBuffer(stream) {
  const reader = stream.getReader();
  const chunks = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  let length = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
  let result = new Uint8Array(length);
  let offset = 0;
  for (let chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result.buffer;
}

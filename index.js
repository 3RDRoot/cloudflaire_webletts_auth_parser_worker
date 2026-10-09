import PostalMime from 'postal-mime';

export default {
  async email(message, env, ctx) {
    try {
      // 1. Parse the raw incoming email stream using postal-mime
      const rawEmail = await readStreamToBuffer(message.raw);
      const parser = new PostalMime();
      const emailParsed = await parser.parse(rawEmail);

      const senderEmail = message.from;
      const emailBody = emailParsed.text || '';

      // 2. Extract your unique token from the email body using regex 
      // (Assuming your tokens match a pattern like 'reg_xxxxx' or alphanumeric strings)
      const tokenMatch = emailBody.match(/[a-zA-Z0-9_\-]{8,32}/);
      
      if (!tokenMatch) {
        console.log(`No valid token found in email from: ${senderEmail}`);
        message.setReject("No valid authentication token found in email body.");
        return;
      }

      const extractedToken = tokenMatch[0];

      // 3. Securely forward the verified token & sender to your backend server
      const backendResponse = await fetch(env.BACKEND_VERIFY_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Worker-Secret': env.WORKER_SECRET_KEY, // Protect your backend endpoint
        },
        body: JSON.stringify({
          token: extractedToken,
          sender: senderEmail,
        }),
      });

      if (!backendResponse.ok) {
        console.error(`Backend failed to process token: ${backendResponse.status}`);
        message.setReject("Authentication failed on server.");
        return;
      }

      console.log(`Successfully authenticated token for sender: ${senderEmail}`);
    } catch (err) {
      console.error("Error processing inbound email:", err);
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

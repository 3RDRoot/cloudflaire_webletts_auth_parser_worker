import { Buffer } from 'node:buffer';
import { DkimVerifier } from 'mailauth/lib/dkim/dkim-verifier.js';
import { writeToStream } from 'mailauth/lib/tools.js';

// Workerd's node:crypto accepts "sha256", but not Node's "rsa-sha256" alias.
// Adapt the digest name for RSA verification without changing global crypto APIs
// or the DKIM algorithm/policy/body checks performed by mailauth.
class WorkerDkimVerifier extends DkimVerifier {
  async verifySignature(signature, fallback) {
    const algorithm = signature.algorithm;
    if (signature.signAlgo === 'rsa') signature.algorithm = signature.hashAlgo;
    try { return await super.verifySignature(signature, fallback); }
    finally { signature.algorithm = algorithm; }
  }
}

export async function verifyDkim(raw, options) {
  const verifier = new WorkerDkimVerifier(options);
  await writeToStream(verifier, Buffer.from(raw));
  return { headerFrom: verifier.headerFrom, fromFields: verifier.fromFields,
    fromSyntax: verifier.fromSyntax, results: verifier.results };
}

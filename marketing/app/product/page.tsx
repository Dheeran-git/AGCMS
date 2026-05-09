export default function ProductPage() {
  return (
    <article className="mx-auto max-w-prose px-6 py-16 prose prose-invert">
      <h1 className="text-4xl font-semibold mb-6">How AGCMS works</h1>

      <p className="text-fg-muted">
        AGCMS is an OpenAI-compatible reverse proxy with a 13-step request
        lifecycle. Every request goes through authentication, rate limiting,
        PII scanning, prompt-injection detection, policy resolution, and
        signed audit before reaching the upstream LLM.
      </p>

      <h2 className="text-2xl font-semibold mt-10 mb-3">The 13 steps</h2>
      <ol className="list-decimal pl-6 space-y-1 text-fg-muted">
        <li>Parse request</li>
        <li>Per-IP global rate limit</li>
        <li>Authenticate (API key or JWT)</li>
        <li>Per-tenant rate limit</li>
        <li>PII scan (parallel)</li>
        <li>Prompt-injection scan (parallel)</li>
        <li>Policy resolution (ALLOW / REDACT / BLOCK / ESCALATE)</li>
        <li>Enforce — block, redact, or escalate</li>
        <li>Forward to LLM (Groq / Gemini / Mistral / Ollama)</li>
        <li>Response compliance check</li>
        <li>HMAC-signed, hash-chained audit row</li>
        <li>Nightly Merkle anchor to S3 Object Lock</li>
        <li>Deliver response with X-AGCMS-Interaction-ID</li>
      </ol>

      <h2 className="text-2xl font-semibold mt-10 mb-3">Three-line integration</h2>
      <pre className="bg-panel border border-border rounded-md p-4 overflow-x-auto text-sm">
{`from openai import OpenAI
from agcms import openai_wrap

client = openai_wrap(OpenAI(api_key="..."), agcms_base_url="...", agcms_api_key="...")`}
      </pre>
    </article>
  );
}

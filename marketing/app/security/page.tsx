const POSTURE = [
  { name: "SOC 2 Type II", state: "In observation (Vanta) — report Q3 2026" },
  { name: "Penetration test", state: "Scheduled — Cure53, week 14" },
  { name: "Encryption at rest", state: "AES-256-GCM via envelope encryption" },
  { name: "Encryption in transit", state: "TLS 1.3 only" },
  { name: "SSO", state: "SAML / OIDC via WorkOS — 40+ identity providers" },
  { name: "MFA", state: "TOTP enforced for admin & compliance roles" },
  { name: "Audit chain", state: "HMAC-SHA256, hash-chained, Merkle-anchored to S3 Object Lock" },
  { name: "Key rotation", state: "Active rotation procedure with historical-row verification" },
];

const SUBPROCESSORS = [
  ["AWS", "Compute, storage, KMS, S3 Object Lock", "USA / EU"],
  ["WorkOS", "SSO / SAML / OIDC", "USA"],
  ["Stripe", "Billing", "USA"],
  ["Vanta", "SOC 2 evidence collection", "USA"],
  ["Better Stack", "Status page + ops uptime monitoring", "USA"],
  ["Anthropic / OpenAI / Groq", "LLM inference (per tenant choice)", "USA"],
];

export default function SecurityPage() {
  return (
    <div className="mx-auto max-w-5xl px-6 py-16 space-y-14">
      <header>
        <h1 className="text-4xl font-semibold mb-3">Trust & Security</h1>
        <p className="text-fg-muted">
          A public mirror of the in-app Trust Center. The same audit-bundle
          verifier that auditors use is embedded on the home page — try it.
        </p>
      </header>

      <section>
        <h2 className="text-2xl font-semibold mb-4">Security posture</h2>
        <ul className="border border-border rounded-lg divide-y divide-border bg-panel">
          {POSTURE.map(({ name, state }) => (
            <li key={name} className="px-5 py-3 text-sm flex justify-between">
              <span className="font-medium">{name}</span>
              <span className="text-fg-muted">{state}</span>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2 className="text-2xl font-semibold mb-4">Subprocessors</h2>
        <div className="border border-border rounded-lg overflow-hidden bg-panel">
          <table className="w-full text-sm">
            <thead className="text-fg-subtle text-xs uppercase">
              <tr>
                <th className="text-left px-5 py-3">Vendor</th>
                <th className="text-left px-5 py-3">Purpose</th>
                <th className="text-left px-5 py-3">Region</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {SUBPROCESSORS.map(([v, p, r]) => (
                <tr key={v}>
                  <td className="px-5 py-3 font-medium">{v}</td>
                  <td className="px-5 py-3 text-fg-muted">{p}</td>
                  <td className="px-5 py-3 text-fg-muted">{r}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

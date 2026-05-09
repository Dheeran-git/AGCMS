import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Privacy Policy · AGCMS",
};

export default function PrivacyPage() {
  return (
    <article className="mx-auto max-w-prose px-6 py-16 prose prose-invert">
      <h1 className="text-4xl font-semibold mb-3">Privacy Policy</h1>
      <p className="text-fg-subtle text-sm mb-10">
        Last updated: 2026-04-22 · Placeholder. The authoritative version is
        attached as Schedule A to your Master Services Agreement.
      </p>

      <Section title="What we collect">
        <ul className="list-disc pl-5 text-sm text-fg-muted space-y-1">
          <li>Account profile (name, email, role, tenant subdomain).</li>
          <li>API request metadata routed through the gateway.</li>
          <li>Audit log entries you produce inside your tenant.</li>
          <li>Operational telemetry (latency, error counts) — never request bodies.</li>
        </ul>
      </Section>

      <Section title="What we do not collect">
        <ul className="list-disc pl-5 text-sm text-fg-muted space-y-1">
          <li>Plaintext request or response bodies are never written to disk in cleartext.</li>
          <li>We do not train models on your traffic.</li>
          <li>We do not sell or share customer data with third parties for advertising.</li>
        </ul>
      </Section>

      <Section title="Where data is stored">
        <p className="text-sm text-fg-muted">
          AWS — region of your choosing (us-east-1, us-west-2, eu-west-1,
          eu-central-1). Audit anchors are written to S3 Object Lock in the same
          region as your tenant.
        </p>
      </Section>

      <Section title="Subprocessors">
        <p className="text-sm text-fg-muted">
          See the{" "}
          <a href="/security" className="text-accent hover:text-accent-bright">
            security page
          </a>{" "}
          for the full subprocessor list.
        </p>
      </Section>

      <Section title="Your rights">
        <ul className="list-disc pl-5 text-sm text-fg-muted space-y-1">
          <li>Access — export your data via the dashboard or API at any time.</li>
          <li>Erasure (GDPR Article 17) — two-admin approval; PII tombstoned without breaking the audit chain.</li>
          <li>Portability — bundle export ships JSONL + verifier.</li>
        </ul>
      </Section>

      <Section title="Contact">
        <p className="text-sm text-fg-muted">
          Privacy questions: <a className="text-accent hover:text-accent-bright" href="mailto:privacy@agcms.com">privacy@agcms.com</a>.
          Security disclosures: <a className="text-accent hover:text-accent-bright" href="mailto:security@agcms.com">security@agcms.com</a>.
        </p>
      </Section>
    </article>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-8">
      <h2 className="text-xl font-semibold mb-3">{title}</h2>
      {children}
    </section>
  );
}

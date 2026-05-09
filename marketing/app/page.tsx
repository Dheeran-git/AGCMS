import Link from "next/link";
import { BundleVerifier } from "@/components/BundleVerifier";

export default function HomePage() {
  return (
    <>
      <section className="mx-auto max-w-5xl px-6 pt-24 pb-16 text-center">
        <span className="inline-block text-xs uppercase tracking-[0.2em] text-fg-subtle mb-5">
          AI Governance · Live runtime · Multi-tenant
        </span>
        <h1 className="text-5xl md:text-6xl font-semibold tracking-tight leading-[1.05]">
          A legally defensible audit trail
          <br />
          for every AI request your company sends.
        </h1>
        <p className="mt-6 max-w-2xl mx-auto text-lg text-fg-muted">
          AGCMS sits in front of your LLM traffic, redacts PII, blocks prompt
          injection, and writes a cryptographically signed audit log that an
          external auditor can verify offline — no AGCMS credentials required.
        </p>
        <div className="mt-9 flex justify-center gap-3">
          <Link
            href="/book-demo"
            className="bg-accent hover:bg-accent-bright text-white text-sm px-5 py-2.5 rounded-md"
          >
            Book a 30-minute demo
          </Link>
          <Link
            href="/product"
            className="border border-border text-sm px-5 py-2.5 rounded-md hover:border-fg-muted"
          >
            How it works
          </Link>
        </div>
      </section>

      <section className="mx-auto max-w-5xl px-6 pb-16">
        <h2 className="text-2xl font-semibold mb-2">
          Verify a real audit bundle, right here.
        </h2>
        <p className="text-fg-muted mb-6">
          Drop a bundle exported from any AGCMS tenant. Verification runs in
          your browser — nothing is uploaded.
        </p>
        <BundleVerifier />
      </section>

      <section className="mx-auto max-w-5xl px-6 pb-24 grid md:grid-cols-3 gap-6">
        {[
          {
            title: "Cryptographic chain of custody",
            body:
              "Every audit row is HMAC-signed and chained to the previous row. Daily Merkle roots are anchored to S3 Object Lock — tampering is mathematically detectable.",
          },
          {
            title: "Multi-tenant enforcement plane",
            body:
              "Postgres row-level security from day one. SSO via WorkOS, MFA, scoped API keys, session revocation, GDPR Art. 17 purge with dual approval.",
          },
          {
            title: "Compliance maps to your framework",
            body:
              "Out-of-the-box policy packs for HIPAA, GDPR, EU AI Act high-risk, NIST AI RMF, SOC 2 CC, and PCI-DSS — every finding cites the article it satisfies.",
          },
        ].map((card) => (
          <div
            key={card.title}
            className="border border-border rounded-lg p-5 bg-panel"
          >
            <h3 className="font-medium mb-2">{card.title}</h3>
            <p className="text-sm text-fg-muted">{card.body}</p>
          </div>
        ))}
      </section>
    </>
  );
}

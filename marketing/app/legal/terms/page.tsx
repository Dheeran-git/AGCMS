import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Terms of Service · AGCMS",
};

export default function TermsPage() {
  return (
    <article className="mx-auto max-w-prose px-6 py-16 prose prose-invert">
      <h1 className="text-4xl font-semibold mb-3">Terms of Service</h1>
      <p className="text-fg-subtle text-sm mb-10">
        Last updated: 2026-04-22 · Placeholder. Negotiated MSA terms supersede
        these for Business and Enterprise customers.
      </p>

      <Section title="Acceptable use">
        <p className="text-sm text-fg-muted">
          AGCMS may not be used to defeat the safety or compliance posture of
          any third party, to evade lawful audit, or to process data the
          customer is not lawfully entitled to process.
        </p>
      </Section>

      <Section title="Service tiers">
        <p className="text-sm text-fg-muted">
          See <a className="text-accent hover:text-accent-bright" href="/pricing">pricing</a> for current
          tier limits and SLA targets. SLAs are fixed in the MSA for Business
          and Enterprise customers.
        </p>
      </Section>

      <Section title="Data ownership">
        <p className="text-sm text-fg-muted">
          You own your traffic, your audit logs, and any policies you author.
          AGCMS is a data processor — never a controller — for tenant traffic.
        </p>
      </Section>

      <Section title="Termination">
        <p className="text-sm text-fg-muted">
          Either party may terminate for material breach with 30 days' notice
          and an opportunity to cure. On termination, your tenant data is
          available for export for 60 days; audit anchors persist for the
          retention period configured in your MSA (default 7 years).
        </p>
      </Section>

      <Section title="Liability">
        <p className="text-sm text-fg-muted">
          To the maximum extent permitted by law, AGCMS's aggregate liability
          is capped at the fees paid in the 12 months preceding the claim. The
          MSA may provide expanded remedies for compliance-driven damages.
        </p>
      </Section>

      <Section title="Governing law">
        <p className="text-sm text-fg-muted">
          Delaware, USA. Disputes resolved via binding arbitration unless the
          MSA specifies otherwise.
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

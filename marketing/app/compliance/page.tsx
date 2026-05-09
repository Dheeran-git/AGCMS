import Link from "next/link";

const FRAMEWORKS = [
  { slug: "hipaa", name: "HIPAA", description: "US healthcare PHI handling — §164.312(b) audit controls." },
  { slug: "gdpr", name: "GDPR", description: "EU personal data — Art. 17 erasure, Art. 30 records of processing." },
  { slug: "eu-ai-act", name: "EU AI Act (high-risk)", description: "Art. 13 transparency, Art. 12 record-keeping for high-risk systems." },
  { slug: "nist-ai-rmf", name: "NIST AI RMF", description: "Govern · Map · Measure · Manage controls for AI risk." },
  { slug: "soc2", name: "SOC 2 (CC)", description: "Common Criteria — CC6 logical access, CC7 system operations." },
  { slug: "pci-dss", name: "PCI-DSS", description: "Cardholder-data leakage prevention in AI workflows." },
];

export default function CompliancePage() {
  return (
    <div className="mx-auto max-w-5xl px-6 py-16">
      <h1 className="text-4xl font-semibold mb-3">Compliance</h1>
      <p className="text-fg-muted mb-10">
        AGCMS ships policy packs for the regulatory frameworks our buyers
        actually face. Each finding in your audit log links back to the
        specific article it satisfies.
      </p>

      <ul className="grid md:grid-cols-2 gap-4">
        {FRAMEWORKS.map((f) => (
          <li
            key={f.slug}
            className="border border-border rounded-lg p-5 bg-panel"
          >
            <Link href={`/compliance/${f.slug}` as any} className="block">
              <h2 className="text-lg font-medium mb-1">{f.name}</h2>
              <p className="text-sm text-fg-muted">{f.description}</p>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

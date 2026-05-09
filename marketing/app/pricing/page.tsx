import Link from "next/link";

const TIERS = [
  {
    name: "Starter",
    price: "$499 / mo",
    audience: "Single team, < 1 M requests / month.",
    cta: { href: "/signup", label: "Start free trial" },
    features: [
      "OpenAI-compatible gateway",
      "PII redaction + injection detection",
      "Signed audit log + bundle export",
      "Email support",
    ],
  },
  {
    name: "Business",
    price: "From $2 500 / mo",
    audience: "Compliance team, < 25 M requests / month.",
    cta: { href: "/book-demo", label: "Talk to sales" },
    features: [
      "Everything in Starter",
      "SSO (WorkOS) + MFA",
      "Policy packs (HIPAA, GDPR, EU AI Act, NIST, SOC 2, PCI)",
      "Slack / PagerDuty / webhook / Splunk integrations",
      "Slack support, < 4h response",
    ],
    highlight: true,
  },
  {
    name: "Enterprise",
    price: "Custom",
    audience: "Regulated enterprise, VPC / BYOK.",
    cta: { href: "/book-demo", label: "Request enterprise demo" },
    features: [
      "Everything in Business",
      "Dedicated VPC deployment",
      "Bring-your-own-key (BYOK)",
      "SOC 2 Type II report on request",
      "Dedicated CSM, 99.95% SLA",
    ],
  },
];

export default function PricingPage() {
  return (
    <div className="mx-auto max-w-6xl px-6 py-16">
      <h1 className="text-4xl font-semibold mb-3">Pricing</h1>
      <p className="text-fg-muted mb-10">
        Three tiers. Public price for Starter; Business and Enterprise are
        scoped to your traffic and integration needs.
      </p>

      <div className="grid md:grid-cols-3 gap-5">
        {TIERS.map((t) => (
          <div
            key={t.name}
            className={`border rounded-lg p-6 bg-panel ${
              t.highlight ? "border-accent" : "border-border"
            }`}
          >
            <h2 className="text-lg font-medium">{t.name}</h2>
            <p className="text-2xl font-semibold mt-1">{t.price}</p>
            <p className="text-sm text-fg-muted mt-1">{t.audience}</p>

            <ul className="mt-5 space-y-1.5 text-sm text-fg-muted">
              {t.features.map((f) => (
                <li key={f}>• {f}</li>
              ))}
            </ul>

            <Link
              href={t.cta.href as any}
              className="mt-6 inline-block bg-accent hover:bg-accent-bright text-white text-sm px-4 py-2 rounded-md"
            >
              {t.cta.label}
            </Link>
          </div>
        ))}
      </div>
    </div>
  );
}

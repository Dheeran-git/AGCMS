import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Status · AGCMS",
  description:
    "Live availability, recent incidents, and historic uptime for the AGCMS gateway, dashboard, and audit chain.",
};

const COMPONENTS = [
  { name: "Gateway (api.agcms.com)", state: "Operational", target: "99.95%" },
  { name: "Dashboard (app.agcms.com)", state: "Operational", target: "99.9%" },
  { name: "Audit chain writer", state: "Operational", target: "99.99%" },
  { name: "Public verifier (/trust/verify)", state: "Operational", target: "99.9%" },
  { name: "WorkOS SSO bridge", state: "Operational", target: "99.9%" },
  { name: "Notifications dispatcher", state: "Operational", target: "99.5%" },
];

const SLA = [
  ["Enterprise", "99.95% gateway availability", "Service credits per MSA"],
  ["Business", "99.9% gateway availability", "Service credits per MSA"],
  ["Starter", "Best-effort", "—"],
];

export default function StatusPage() {
  return (
    <div className="mx-auto max-w-5xl px-6 py-16 space-y-14">
      <header>
        <h1 className="text-4xl font-semibold mb-3">System status</h1>
        <p className="text-fg-muted">
          Real-time uptime, incident history, and component-level health is
          published at{" "}
          <a
            href="https://status.agcms.com"
            className="text-accent hover:text-accent-bright"
            target="_blank"
            rel="noopener noreferrer"
          >
            status.agcms.com
          </a>{" "}
          (powered by Better Stack). The mirror below reflects the most recent
          probe.
        </p>
      </header>

      <section>
        <h2 className="text-2xl font-semibold mb-4">Components</h2>
        <ul className="border border-border rounded-lg divide-y divide-border bg-panel">
          {COMPONENTS.map(({ name, state, target }) => (
            <li
              key={name}
              className="px-5 py-3 text-sm flex items-center justify-between"
            >
              <span className="font-medium">{name}</span>
              <div className="flex items-center gap-4">
                <span className="text-fg-subtle text-xs">SLA {target}</span>
                <span className="inline-flex items-center gap-2 text-fg-muted">
                  <span className="inline-block h-2 w-2 rounded-full bg-emerald-500" />
                  {state}
                </span>
              </div>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2 className="text-2xl font-semibold mb-4">SLA tiers</h2>
        <div className="border border-border rounded-lg overflow-hidden bg-panel">
          <table className="w-full text-sm">
            <thead className="text-fg-subtle text-xs uppercase">
              <tr>
                <th className="text-left px-5 py-3">Plan</th>
                <th className="text-left px-5 py-3">Uptime target</th>
                <th className="text-left px-5 py-3">Remedy</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {SLA.map(([plan, target, remedy]) => (
                <tr key={plan}>
                  <td className="px-5 py-3 font-medium">{plan}</td>
                  <td className="px-5 py-3 text-fg-muted">{target}</td>
                  <td className="px-5 py-3 text-fg-muted">{remedy}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="border border-border rounded-lg p-5 bg-panel text-sm text-fg-muted">
        <p>
          Want to be paged on incidents? Subscribe at{" "}
          <a
            href="https://status.agcms.com"
            className="text-accent hover:text-accent-bright"
            target="_blank"
            rel="noopener noreferrer"
          >
            status.agcms.com
          </a>
          , or wire AGCMS itself into PagerDuty / Slack via{" "}
          <Link
            href="/product"
            className="text-accent hover:text-accent-bright"
          >
            Notifications
          </Link>
          .
        </p>
      </section>
    </div>
  );
}

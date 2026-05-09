import type { Metadata } from "next";

export const metadata: Metadata = { title: "Changelog · AGCMS" };

interface Section { label: string; items: string[]; }
interface Entry { version: string; date: string | null; sections: Section[]; }

async function loadChangelog(): Promise<Entry[]> {
  const url = process.env.AGCMS_API_URL ?? "http://localhost:8000";
  try {
    const res = await fetch(`${url}/api/v1/changelog`, { next: { revalidate: 300 } });
    if (!res.ok) return [];
    return (await res.json()) as Entry[];
  } catch {
    return [];
  }
}

export default async function ChangelogPage() {
  const entries = await loadChangelog();

  return (
    <article className="mx-auto max-w-prose px-6 py-16">
      <h1 className="text-4xl font-semibold mb-3">Changelog</h1>
      <p className="text-fg-muted mb-10">
        Sourced from the same feed the in-app Settings → Changelog tab uses.
      </p>

      {entries.length === 0 && (
        <p className="text-fg-muted italic">No releases recorded yet.</p>
      )}

      <ol className="space-y-10">
        {entries.map((entry) => (
          <li key={entry.version} className="border-l-2 border-border pl-6">
            <header className="flex items-baseline gap-3 mb-3">
              <span className="font-mono text-sm">v{entry.version}</span>
              {entry.date && (
                <span className="text-xs text-fg-subtle">{entry.date}</span>
              )}
            </header>
            <div className="space-y-4">
              {entry.sections.map((s) => (
                <div key={s.label}>
                  <div className="text-xs uppercase tracking-wider text-fg-subtle mb-1">
                    {s.label}
                  </div>
                  <ul className="list-disc pl-5 text-sm text-fg-muted space-y-0.5">
                    {s.items.map((item, i) => (
                      <li key={i}>{item}</li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </li>
        ))}
      </ol>
    </article>
  );
}

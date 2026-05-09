"use client";

/**
 * Embedded paste-a-bundle verifier for the marketing landing page.
 *
 * For brevity in the skeleton: this component renders an upload control and
 * delegates verification to the dashboard's public verifier route. A future
 * iteration can port the chain + Merkle checks to client-side WebCrypto so the
 * file genuinely never leaves the browser.
 */

import { useState } from "react";

export function BundleVerifier() {
  const [name, setName] = useState<string | null>(null);

  return (
    <div className="border border-border rounded-lg p-6 bg-panel">
      <label className="block text-sm text-fg-muted mb-3">
        Upload a bundle ZIP
      </label>
      <div className="flex items-center gap-3">
        <input
          type="file"
          accept=".zip"
          onChange={(e) => setName(e.target.files?.[0]?.name ?? null)}
          className="text-sm"
        />
        <a
          href="https://github.com/Dheeran-git/AGCMS/blob/master/tools/verify.py"
          target="_blank"
          rel="noopener noreferrer"
          className="bg-accent hover:bg-accent-bright text-white text-sm px-4 py-2 rounded-md"
        >
          View verifier source
        </a>
      </div>
      {name && (
        <p className="mt-3 text-xs text-fg-subtle font-mono">selected: {name}</p>
      )}
      <p className="mt-4 text-xs text-fg-subtle">
        Or run <code className="font-mono text-fg-muted">pip install agcms &amp;&amp; agcms verify bundle.zip</code> locally.
      </p>
    </div>
  );
}

import { useState, useRef, type DragEvent } from 'react';
import { ShieldCheck, ShieldAlert, Upload, Loader2, Info, CheckCircle2, XCircle, FileText, Lock, ExternalLink } from 'lucide-react';
import { verifyBundle, type VerificationReport, type CheckResult } from '../lib/bundleVerifier';
import { Card, CardContent } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';

type Phase = 'idle' | 'verifying' | 'done' | 'error';

export function PublicVerifier() {
  const [phase, setPhase] = useState<Phase>('idle');
  const [report, setReport] = useState<VerificationReport | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  async function handleFile(file: File) {
    setFileName(file.name);
    setPhase('verifying');
    setErrorMessage(null);
    setReport(null);
    try {
      const r = await verifyBundle(file);
      setReport(r);
      setPhase('done');
    } catch (exc) {
      setErrorMessage((exc as Error).message);
      setPhase('error');
    }
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) void handleFile(file);
  }

  function reset() {
    setPhase('idle');
    setReport(null);
    setErrorMessage(null);
    setFileName(null);
    if (inputRef.current) inputRef.current.value = '';
  }

  return (
    <div className="min-h-screen bg-canvas text-fg-primary">
      <header className="border-b border-border">
        <div className="max-w-[1100px] mx-auto px-8 py-5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-8 w-8 rounded-md bg-accent/15 border border-accent/30 flex items-center justify-center">
              <ShieldCheck className="h-4 w-4 text-accent" />
            </div>
            <div>
              <div className="text-caption font-semibold tracking-tight">AGCMS Trust Center</div>
              <div className="text-label text-fg-muted">Public audit bundle verifier</div>
            </div>
          </div>
          <a
            href="/"
            className="text-label text-fg-muted hover:text-fg-primary transition inline-flex items-center gap-1.5"
          >
            Dashboard <ExternalLink className="h-3 w-3" />
          </a>
        </div>
      </header>

      <main className="max-w-[1100px] mx-auto px-8 py-12">
        <div className="mb-10 text-center">
          <span className="inline-flex items-center px-3 py-1 rounded-full bg-accent/10 border border-accent/30 text-micro uppercase tracking-wider text-accent-bright mb-6">
            Public verifier
          </span>
          <h1 className="text-display tracking-[-1.056px] font-[510] mb-5 max-w-3xl mx-auto leading-tight">
            Prove your audit log<br />has not been altered.
          </h1>
          <p className="text-body text-fg-muted max-w-2xl mx-auto leading-relaxed">
            Drop an AGCMS audit bundle below. Verification runs entirely in your
            browser — no file contents leave this device, no AGCMS credentials
            required.
          </p>
        </div>

        {phase === 'idle' && (
          <DropZone
            dragOver={dragOver}
            setDragOver={setDragOver}
            onDrop={onDrop}
            onPick={() => inputRef.current?.click()}
          />
        )}

        {phase === 'verifying' && (
          <Card className="p-10">
            <div className="flex items-center gap-4">
              <Loader2 className="h-6 w-6 animate-spin text-accent" />
              <div>
                <div className="text-body font-medium">Verifying bundle</div>
                <div className="text-label text-fg-muted">{fileName}</div>
              </div>
            </div>
          </Card>
        )}

        {phase === 'error' && (
          <Card className="p-8 border-danger/40">
            <div className="flex items-start gap-3">
              <XCircle className="h-5 w-5 text-danger mt-0.5 shrink-0" />
              <div className="flex-1">
                <div className="text-body font-medium text-danger mb-1">
                  Bundle could not be read
                </div>
                <div className="text-label text-fg-muted font-mono break-all">
                  {errorMessage}
                </div>
                <Button variant="outline" size="sm" className="mt-4" onClick={reset}>
                  Try another bundle
                </Button>
              </div>
            </div>
          </Card>
        )}

        {phase === 'done' && report && (
          <ResultView report={report} fileName={fileName} onReset={reset} />
        )}

        <input
          ref={inputRef}
          type="file"
          accept=".zip,application/zip"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) void handleFile(f);
          }}
        />

        <section className="mt-14 grid gap-5 sm:grid-cols-3">
          <Card className="p-5">
            <Lock className="h-4 w-4 text-accent mb-3" />
            <div className="text-caption font-medium mb-1">Zero-trust verification</div>
            <div className="text-label text-fg-muted leading-relaxed">
              Bundle never leaves this browser. Hashing uses the Web Crypto API
              — SHA-256 computed locally.
            </div>
          </Card>
          <Card className="p-5">
            <FileText className="h-4 w-4 text-accent mb-3" />
            <div className="text-caption font-medium mb-1">What we check</div>
            <div className="text-label text-fg-muted leading-relaxed">
              Per-tenant chain continuity (no gaps, reorders, or broken links)
              and Merkle-root recomputation against the published manifest.
            </div>
          </Card>
          <Card className="p-5">
            <ShieldCheck className="h-4 w-4 text-accent mb-3" />
            <div className="text-caption font-medium mb-1">External anchor</div>
            <div className="text-label text-fg-muted leading-relaxed">
              Roots are cross-referenced against S3 Object Lock (Compliance
              mode) — immutable even to AGCMS operators.
            </div>
          </Card>
        </section>

        <footer className="mt-16 pt-8 border-t border-border text-label text-fg-muted">
          <p>
            For the offline-capable stdlib-only reference verifier, see{' '}
            <code className="font-mono text-fg-secondary">verify.py</code> inside
            the bundle ZIP. Same checks, no browser needed.
          </p>
        </footer>
      </main>
    </div>
  );
}

function DropZone({
  dragOver,
  setDragOver,
  onDrop,
  onPick,
}: {
  dragOver: boolean;
  setDragOver: (v: boolean) => void;
  onDrop: (e: DragEvent<HTMLDivElement>) => void;
  onPick: () => void;
}) {
  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={onDrop}
      onClick={onPick}
      className={`cursor-pointer rounded-lg border-2 border-dashed transition p-16 text-center
        ${dragOver ? 'border-accent bg-accent/5' : 'border-border hover:border-accent/50 bg-surface/40'}`}
    >
      <Upload className="h-8 w-8 mx-auto mb-4 text-fg-muted" />
      <div className="text-body font-medium mb-1">Drop a bundle ZIP here</div>
      <div className="text-label text-fg-muted">
        or <span className="text-accent">click to pick a file</span>
      </div>
      <div className="text-label text-fg-muted mt-4">
        Files typically named{' '}
        <code className="font-mono">agcms-bundle-&lt;tenant&gt;-&lt;date&gt;.zip</code>
      </div>
    </div>
  );
}

function ResultView({
  report,
  fileName,
  onReset,
}: {
  report: VerificationReport;
  fileName: string | null;
  onReset: () => void;
}) {
  const failCount = report.checks.filter((c) => c.status === 'fail').length;
  const passCount = report.checks.filter((c) => c.status === 'pass').length;

  return (
    <div className="space-y-6">
      <Card
        className={`p-8 ${
          report.ok ? 'border-success/40 bg-success/5' : 'border-danger/40 bg-danger/5'
        }`}
      >
        <div className="flex items-start gap-4">
          {report.ok ? (
            <ShieldCheck className="h-10 w-10 text-success shrink-0" />
          ) : (
            <ShieldAlert className="h-10 w-10 text-danger shrink-0" />
          )}
          <div className="flex-1">
            <div className={`text-h2 font-semibold ${report.ok ? 'text-success' : 'text-danger'}`}>
              {report.ok ? 'Bundle is intact' : 'Bundle integrity FAILED'}
            </div>
            <div className="text-label text-fg-muted mt-1">
              {fileName} — {passCount} passed, {failCount} failed
            </div>
          </div>
          <Button variant="outline" size="sm" onClick={onReset}>
            Verify another
          </Button>
        </div>
      </Card>

      <Card>
        <CardContent className="p-6">
          <div className="text-caption font-medium mb-4 tracking-tight">Bundle metadata</div>
          <dl className="grid grid-cols-2 gap-x-8 gap-y-2.5 text-label">
            <dt className="text-fg-muted">Tenant</dt>
            <dd className="font-mono">{report.metadata.tenant_id}</dd>
            <dt className="text-fg-muted">Period</dt>
            <dd className="font-mono">
              {report.metadata.period_start} → {report.metadata.period_end}
            </dd>
            <dt className="text-fg-muted">Generated at</dt>
            <dd className="font-mono">{report.metadata.generated_at}</dd>
            <dt className="text-fg-muted">Rows</dt>
            <dd className="font-mono">{report.rowCount}</dd>
            <dt className="text-fg-muted">Roots</dt>
            <dd className="font-mono">{report.rootCount}</dd>
            <dt className="text-fg-muted">Scheme</dt>
            <dd className="font-mono">{report.metadata.tree_scheme}</dd>
          </dl>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-6">
          <div className="text-caption font-medium mb-4 tracking-tight">Checks</div>
          <div className="space-y-3">
            {report.checks.map((c, i) => (
              <CheckRow key={i} check={c} />
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function CheckRow({ check }: { check: CheckResult }) {
  const icon =
    check.status === 'pass' ? (
      <CheckCircle2 className="h-4 w-4 text-success" />
    ) : check.status === 'fail' ? (
      <XCircle className="h-4 w-4 text-danger" />
    ) : (
      <Info className="h-4 w-4 text-fg-muted" />
    );
  const badge =
    check.status === 'pass' ? (
      <Badge variant="success">PASS</Badge>
    ) : check.status === 'fail' ? (
      <Badge variant="danger">FAIL</Badge>
    ) : (
      <Badge variant="neutral">INFO</Badge>
    );
  return (
    <div className="flex items-start gap-3 py-2 border-b border-border last:border-b-0">
      <div className="mt-0.5">{icon}</div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          {badge}
          <div className="text-label font-medium">{check.message}</div>
        </div>
        {check.detail && (
          <div className="text-label text-fg-muted mt-1 font-mono break-all">
            {check.detail}
          </div>
        )}
      </div>
    </div>
  );
}

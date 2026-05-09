import { useState } from 'react';
import { FileText, Scale, Download, Check, X, AlertTriangle } from 'lucide-react';
import {
  fetchComplianceReport,
  type GDPRReport,
  type EUAIActReport,
  type ComplianceReport,
} from '../lib/api';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';

type ReportType = 'gdpr' | 'eu-ai-act';

interface ReportCard {
  type: ReportType;
  title: string;
  description: string;
  icon: typeof FileText;
}

const REPORT_CARDS: ReportCard[] = [
  {
    type: 'gdpr',
    title: 'GDPR Article 30 Report',
    description:
      'Records of Processing Activities — PII categories, retention policy, cross-border transfers, and detection summary for the last 30 days.',
    icon: FileText,
  },
  {
    type: 'eu-ai-act',
    title: 'EU AI Act Compliance Report',
    description:
      'Article 13 Transparency — AI system classification, injection detection method, human oversight metrics, and audit trail integrity.',
    icon: Scale,
  },
];

function FindingRow({
  check,
  status,
  detail,
}: {
  check: string;
  status: 'pass' | 'fail' | 'warning';
  detail: string;
}) {
  const Icon = status === 'pass' ? Check : status === 'fail' ? X : AlertTriangle;
  const tone =
    status === 'pass'
      ? 'text-status-success'
      : status === 'fail'
      ? 'text-status-danger'
      : 'text-status-warning';

  return (
    <tr className="border-b border-border-subtle last:border-0">
      <td className="py-2.5 pr-4 w-6">
        <Icon className={`h-4 w-4 ${tone}`} strokeWidth={2} />
      </td>
      <td className="py-2.5 pr-4 text-caption text-fg-secondary">{check}</td>
      <td className="py-2.5 text-caption text-fg-muted">{detail}</td>
    </tr>
  );
}

function StatTile({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="bg-translucent-1 border border-border-subtle rounded-md px-3 py-2.5">
      <p className="text-micro uppercase tracking-wider text-fg-muted">{label}</p>
      <p className="mt-1 text-body-emph text-fg-primary font-mono">{String(value)}</p>
    </div>
  );
}

function GDPRContent({ report }: { report: GDPRReport }) {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        <StatTile label="Total Requests" value={report.total_requests} />
        <StatTile label="PII Detections" value={report.total_pii_detections} />
        <StatTile label="Redacted" value={report.pii_redacted} />
        <StatTile label="Blocked" value={report.pii_blocked} />
        <StatTile label="Escalated" value={report.pii_escalated} />
        <StatTile label="Period" value={report.period} />
      </div>

      <div>
        <p className="text-caption text-fg-secondary mb-2">Data Categories Processed</p>
        <div className="flex flex-wrap gap-1.5">
          {report.data_categories_processed.length > 0 ? (
            report.data_categories_processed.map((cat) => (
              <Badge key={cat} variant="info">
                {cat}
              </Badge>
            ))
          ) : (
            <span className="text-small text-fg-muted italic">None detected</span>
          )}
        </div>
      </div>

      <div className="flex flex-wrap gap-x-8 gap-y-2 text-caption">
        <div>
          <span className="text-fg-muted">Cross-border transfers:</span>{' '}
          <Badge variant={report.cross_border_transfers ? 'warning' : 'subtle'}>
            {report.cross_border_transfers ? 'Yes' : 'No'}
          </Badge>
        </div>
        <div>
          <span className="text-fg-muted">Retention policy:</span>{' '}
          <span className="text-fg-primary font-mono">{report.retention_policy}</span>
        </div>
      </div>

      <div>
        <p className="text-caption text-fg-secondary mb-2">Compliance Findings</p>
        <table className="w-full">
          <tbody>
            {report.findings.map((f) => (
              <FindingRow key={f.check} {...f} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function EUAIActContent({ report }: { report: EUAIActReport }) {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        <StatTile label="System Name" value={report.system_name} />
        <StatTile label="Risk Classification" value={report.risk_classification} />
        <StatTile label="Detection Method" value={report.injection_detection_method} />
        <StatTile label="Escalations (30d)" value={report.human_oversight_escalations} />
        <StatTile label="Pending" value={report.pending_escalations} />
        <StatTile label="Policy Changes (30d)" value={report.policy_changes_30d} />
      </div>

      <div className="flex flex-wrap gap-x-8 gap-y-2 text-caption">
        <div>
          <span className="text-fg-muted">Injection detection:</span>{' '}
          <Badge variant={report.injection_detection_enabled ? 'success' : 'danger'}>
            {report.injection_detection_enabled ? 'Enabled' : 'Disabled'}
          </Badge>
        </div>
        <div>
          <span className="text-fg-muted">Audit trail signed:</span>{' '}
          <Badge variant={report.audit_trail_signed ? 'success' : 'danger'}>
            {report.audit_trail_signed ? 'HMAC-SHA256' : 'No'}
          </Badge>
        </div>
      </div>

      <div>
        <p className="text-caption text-fg-secondary mb-2">Compliance Findings</p>
        <table className="w-full">
          <tbody>
            {report.findings.map((f) => (
              <FindingRow key={f.check} {...f} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function Reports() {
  const [reports, setReports] = useState<Partial<Record<ReportType, ComplianceReport>>>({});
  const [loading, setLoading] = useState<Partial<Record<ReportType, boolean>>>({});
  const [errors, setErrors] = useState<Partial<Record<ReportType, string>>>({});

  async function generate(type: ReportType) {
    setLoading((l) => ({ ...l, [type]: true }));
    setErrors((e) => ({ ...e, [type]: undefined }));
    try {
      const data = await fetchComplianceReport(type);
      setReports((r) => ({ ...r, [type]: data }));
    } catch (err) {
      setErrors((e) => ({ ...e, [type]: String(err) }));
    } finally {
      setLoading((l) => ({ ...l, [type]: false }));
    }
  }

  function downloadReport(type: ReportType) {
    const data = reports[type];
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `agcms_${type}_report_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-h1 text-fg-primary">Compliance Reports</h1>
        <p className="mt-1 text-small text-fg-muted">
          Generate GDPR and EU AI Act compliance documentation.
        </p>
      </header>

      <div className="space-y-6">
        {REPORT_CARDS.map((card) => {
          const report = reports[card.type];
          const isLoading = loading[card.type] ?? false;
          const error = errors[card.type];
          const Icon = card.icon;

          return (
            <Card key={card.type}>
              <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0">
                <div className="flex items-start gap-3 min-w-0">
                  <div className="h-9 w-9 rounded-md bg-accent/15 border border-accent/30 flex items-center justify-center flex-shrink-0">
                    <Icon className="h-4 w-4 text-accent-bright" strokeWidth={1.75} />
                  </div>
                  <div className="min-w-0">
                    <CardTitle>{card.title}</CardTitle>
                    <CardDescription className="mt-1">{card.description}</CardDescription>
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  {report && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => downloadReport(card.type)}
                    >
                      <Download className="h-3.5 w-3.5" />
                      JSON
                    </Button>
                  )}
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={() => void generate(card.type)}
                    disabled={isLoading}
                  >
                    {isLoading ? 'Generating…' : report ? 'Regenerate' : 'Generate'}
                  </Button>
                </div>
              </CardHeader>

              <CardContent>
                {error && (
                  <p className="text-caption text-status-danger">{error}</p>
                )}
                {!report && !error && !isLoading && (
                  <p className="text-small text-fg-muted italic">
                    Click "Generate" to produce this report.
                  </p>
                )}
                {isLoading && (
                  <p className="text-small text-fg-muted">Querying audit database…</p>
                )}
                {report && !isLoading && (
                  <div>
                    <p className="text-label text-fg-subtle mb-5 font-mono">
                      Generated {new Date(report.generated_at).toLocaleString()} · Tenant{' '}
                      {report.tenant_id}
                    </p>
                    {report.report_type === 'gdpr' ? (
                      <GDPRContent report={report as GDPRReport} />
                    ) : (
                      <EUAIActContent report={report as EUAIActReport} />
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

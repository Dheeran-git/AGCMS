import { useState } from 'react';
import { fetchComplianceReport, type GDPRReport, type EUAIActReport, type ComplianceReport } from '../lib/api';

type ReportType = 'gdpr' | 'eu-ai-act';

interface ReportCard {
  type: ReportType;
  title: string;
  description: string;
  icon: string;
}

const REPORT_CARDS: ReportCard[] = [
  {
    type: 'gdpr',
    title: 'GDPR Article 30 Report',
    description: 'Records of Processing Activities — PII categories, retention policy, cross-border transfers, and detection summary for the last 30 days.',
    icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
  },
  {
    type: 'eu-ai-act',
    title: 'EU AI Act Compliance Report',
    description: 'Article 13 Transparency — AI system classification, injection detection method, human oversight metrics, and audit trail integrity.',
    icon: 'M3 6l3 1m0 0l-3 9a5.002 5.002 0 006.001 0M6 7l3 9M6 7l6-2m6 2l3-1m-3 1l-3 9a5.002 5.002 0 006.001 0M18 7l3 9m-3-9l-6-2m0-2v2m0 16V5m0 16H9m3 0h3',
  },
];

function FindingRow({ check, status, detail }: { check: string; status: 'pass' | 'fail' | 'warning'; detail: string }) {
  const icon = status === 'pass' ? '✓' : status === 'fail' ? '✗' : '⚠';
  const cls = status === 'pass'
    ? 'text-green-600'
    : status === 'fail'
    ? 'text-red-600'
    : 'text-yellow-600';

  return (
    <tr className="border-b border-gray-50 last:border-0">
      <td className={`py-2 pr-4 font-medium text-sm ${cls}`}>{icon}</td>
      <td className="py-2 pr-4 text-sm text-gray-700">{check}</td>
      <td className="py-2 text-sm text-gray-500">{detail}</td>
    </tr>
  );
}

function GDPRContent({ report }: { report: GDPRReport }) {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
        {[
          ['Total Requests', report.total_requests],
          ['PII Detections', report.total_pii_detections],
          ['Redacted', report.pii_redacted],
          ['Blocked', report.pii_blocked],
          ['Escalated', report.pii_escalated],
          ['Period', report.period],
        ].map(([label, value]) => (
          <div key={String(label)} className="bg-gray-50 rounded-lg p-3">
            <p className="text-xs text-gray-500">{label}</p>
            <p className="text-lg font-semibold text-gray-800 mt-0.5">{String(value)}</p>
          </div>
        ))}
      </div>
      <div>
        <p className="text-sm font-medium text-gray-700 mb-1">Data Categories Processed</p>
        <div className="flex flex-wrap gap-2">
          {report.data_categories_processed.length > 0
            ? report.data_categories_processed.map((cat) => (
                <span key={cat} className="px-2 py-0.5 bg-indigo-50 text-indigo-700 text-xs rounded-full">{cat}</span>
              ))
            : <span className="text-sm text-gray-400">None detected</span>
          }
        </div>
      </div>
      <div className="flex gap-6 text-sm">
        <div>
          <span className="text-gray-500">Cross-border transfers:</span>{' '}
          <span className="font-medium">{report.cross_border_transfers ? 'Yes' : 'No'}</span>
        </div>
        <div>
          <span className="text-gray-500">Retention policy:</span>{' '}
          <span className="font-medium">{report.retention_policy}</span>
        </div>
      </div>
      <div>
        <p className="text-sm font-medium text-gray-700 mb-2">Compliance Findings</p>
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
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
        {[
          ['System Name', report.system_name],
          ['Risk Classification', report.risk_classification],
          ['Detection Method', report.injection_detection_method],
          ['Escalations (30d)', report.human_oversight_escalations],
          ['Pending', report.pending_escalations],
          ['Policy Changes (30d)', report.policy_changes_30d],
        ].map(([label, value]) => (
          <div key={String(label)} className="bg-gray-50 rounded-lg p-3">
            <p className="text-xs text-gray-500">{label}</p>
            <p className="text-lg font-semibold text-gray-800 mt-0.5">{String(value)}</p>
          </div>
        ))}
      </div>
      <div className="flex gap-6 text-sm">
        <div>
          <span className="text-gray-500">Injection detection:</span>{' '}
          <span className="font-medium">{report.injection_detection_enabled ? 'Enabled' : 'Disabled'}</span>
        </div>
        <div>
          <span className="text-gray-500">Audit trail signed:</span>{' '}
          <span className="font-medium">{report.audit_trail_signed ? 'Yes (HMAC-SHA256)' : 'No'}</span>
        </div>
      </div>
      <div>
        <p className="text-sm font-medium text-gray-700 mb-2">Compliance Findings</p>
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
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Compliance Reports</h1>
        <p className="text-sm text-gray-500 mt-1">Generate GDPR and EU AI Act compliance documentation</p>
      </div>

      <div className="space-y-8">
        {REPORT_CARDS.map((card) => {
          const report = reports[card.type];
          const isLoading = loading[card.type] ?? false;
          const error = errors[card.type];

          return (
            <div key={card.type} className="bg-white rounded-lg border border-gray-200">
              {/* Card header */}
              <div className="px-6 py-5 border-b border-gray-100 flex items-start justify-between gap-4">
                <div className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-lg bg-indigo-50 flex items-center justify-center flex-shrink-0">
                    <svg className="w-5 h-5 text-indigo-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d={card.icon} />
                    </svg>
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-gray-900">{card.title}</h2>
                    <p className="text-sm text-gray-500 mt-0.5">{card.description}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  {report && (
                    <button
                      onClick={() => downloadReport(card.type)}
                      className="px-3 py-1.5 bg-gray-100 text-gray-600 text-sm rounded-md hover:bg-gray-200"
                    >
                      Download JSON
                    </button>
                  )}
                  <button
                    onClick={() => void generate(card.type)}
                    disabled={isLoading}
                    className="px-4 py-1.5 bg-indigo-600 text-white text-sm rounded-md hover:bg-indigo-700 disabled:opacity-50"
                  >
                    {isLoading ? 'Generating…' : report ? 'Regenerate' : 'Generate'}
                  </button>
                </div>
              </div>

              {/* Card body */}
              <div className="px-6 py-5">
                {error && (
                  <p className="text-red-500 text-sm">{error}</p>
                )}
                {!report && !error && !isLoading && (
                  <p className="text-gray-400 text-sm">Click "Generate" to produce this report.</p>
                )}
                {isLoading && (
                  <div className="text-gray-400 text-sm">Querying audit database…</div>
                )}
                {report && !isLoading && (
                  <div>
                    <p className="text-xs text-gray-400 mb-4">
                      Generated: {new Date(report.generated_at).toLocaleString()} —
                      Tenant: {report.tenant_id}
                    </p>
                    {report.report_type === 'gdpr'
                      ? <GDPRContent report={report as GDPRReport} />
                      : <EUAIActContent report={report as EUAIActReport} />
                    }
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

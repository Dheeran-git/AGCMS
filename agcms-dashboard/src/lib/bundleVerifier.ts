/**
 * Client-side audit-bundle verifier.
 *
 * Mirrors `tools/verify.py` but runs entirely in the browser so an
 * auditor can verify an AGCMS audit bundle without sending it to our
 * server — the "trust us less" story is only credible if verification
 * never touches our infrastructure.
 *
 * Hashing uses Web Crypto (SHA-256); ZIP parsing uses JSZip.
 */
import JSZip from 'jszip';

const ZERO_HASH = '0'.repeat(64);
const LEAF_TAG = 0x00;
const NODE_TAG = 0x01;

export interface ChainStart {
  expected_start_sequence: number;
  expected_previous_hash: string;
}

export interface BundleMetadata {
  tenant_id: string;
  generated_at: string;
  period_start: string;
  period_end: string;
  row_count: number;
  chain_starts: Record<string, ChainStart>;
  bundle_schema: string;
  hash_algorithm: string;
  tree_scheme: string;
}

export interface BundleRoot {
  tenant_id: string;
  period_start: string;
  period_end: string;
  row_count: number | null;
  first_sequence_number: number | null;
  last_sequence_number: number | null;
  merkle_root: string;
  signed_root: string;
  anchor_key_id: string;
  s3_url: string | null;
}

export interface BundleRow {
  interaction_id?: string;
  tenant_id: string;
  sequence_number: number;
  previous_log_hash: string;
  log_signature: string;
  signing_key_id?: string;
  [k: string]: unknown;
}

export type CheckStatus = 'pass' | 'fail' | 'info';

export interface CheckResult {
  status: CheckStatus;
  message: string;
  detail?: string;
}

export interface VerificationReport {
  ok: boolean;
  metadata: BundleMetadata;
  rowCount: number;
  rootCount: number;
  checks: CheckResult[];
}

// ─── Primitives ──────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.toLowerCase();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, '0');
  }
  return s;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return new Uint8Array(buf);
}

async function leafHash(sigHex: string): Promise<Uint8Array> {
  const sig = hexToBytes(sigHex);
  const prefixed = new Uint8Array(1 + sig.length);
  prefixed[0] = LEAF_TAG;
  prefixed.set(sig, 1);
  return sha256(prefixed);
}

async function nodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  const combined = new Uint8Array(1 + left.length + right.length);
  combined[0] = NODE_TAG;
  combined.set(left, 1);
  combined.set(right, 1 + left.length);
  return sha256(combined);
}

export async function merkleRoot(signatures: string[]): Promise<string> {
  if (signatures.length === 0) return '00'.repeat(32);
  let level: Uint8Array[] = [];
  for (const sig of signatures) level.push(await leafHash(sig));
  while (level.length > 1) {
    if (level.length % 2 === 1) level.push(level[level.length - 1]);
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(await nodeHash(level[i], level[i + 1]));
    }
    level = next;
  }
  return bytesToHex(level[0]);
}

// ─── Bundle loader ───────────────────────────────────────────────────────────

async function loadBundle(file: File): Promise<{
  metadata: BundleMetadata;
  rows: BundleRow[];
  roots: BundleRoot[];
}> {
  const zip = await JSZip.loadAsync(file);

  const metaFile = zip.file('metadata.json');
  const logsFile = zip.file('logs.jsonl');
  const rootsFile = zip.file('roots.json');

  if (!metaFile || !logsFile || !rootsFile) {
    throw new Error(
      'Bundle is missing one of the required files: metadata.json, logs.jsonl, roots.json',
    );
  }

  const metadata: BundleMetadata = JSON.parse(await metaFile.async('string'));
  const logsText = await logsFile.async('string');
  const roots: BundleRoot[] = JSON.parse(await rootsFile.async('string'));

  const rows: BundleRow[] = [];
  const lines = logsText.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    try {
      rows.push(JSON.parse(line) as BundleRow);
    } catch (exc) {
      throw new Error(`logs.jsonl line ${i + 1} is not valid JSON: ${(exc as Error).message}`);
    }
  }
  return { metadata, rows, roots };
}

// ─── Checks ──────────────────────────────────────────────────────────────────

function checkChain(
  rows: BundleRow[],
  start: ChainStart,
): { ok: boolean; errors: string[] } {
  const errors: string[] = [];
  if (rows.length === 0) return { ok: true, errors };

  const sorted = [...rows].sort(
    (a, b) => (a.sequence_number ?? 0) - (b.sequence_number ?? 0),
  );
  let previous = start.expected_previous_hash;
  let previousSeq = start.expected_start_sequence - 1;

  for (const row of sorted) {
    const seq = row.sequence_number;
    const iid = row.interaction_id ?? '?';
    if (seq === undefined || seq === null) {
      errors.push(`row ${iid} is missing sequence_number`);
      continue;
    }
    if (seq === 0) continue;
    if (seq !== previousSeq + 1) {
      errors.push(
        `gap or reorder: expected sequence_number ${previousSeq + 1}, got ${seq} (row ${iid})`,
      );
    }
    if (row.previous_log_hash !== previous) {
      errors.push(
        `chain break at sequence_number ${seq}: row.previous_log_hash=${row.previous_log_hash} does not match prior row.log_signature=${previous}`,
      );
    }
    const sig = row.log_signature;
    if (typeof sig !== 'string' || sig.length !== 64) {
      errors.push(`row at seq ${seq} has invalid log_signature`);
      previous = ZERO_HASH;
    } else {
      previous = sig;
    }
    previousSeq = seq;
  }

  return { ok: errors.length === 0, errors };
}

async function checkMerkle(
  entry: BundleRoot,
  rowsInPeriod: BundleRow[],
): Promise<{ ok: boolean; errors: string[]; computed: string | null }> {
  const errors: string[] = [];
  const expected = entry.merkle_root;
  if (!expected || expected.length !== 64) {
    errors.push(
      `roots entry for tenant=${entry.tenant_id} period=${entry.period_start}..${entry.period_end} is missing or has malformed merkle_root`,
    );
    return { ok: false, errors, computed: null };
  }
  const sorted = [...rowsInPeriod].sort(
    (a, b) => a.sequence_number - b.sequence_number,
  );
  const sigs = sorted.map((r) => r.log_signature);
  const computed = await merkleRoot(sigs);
  if (computed !== expected) {
    errors.push(
      `Merkle root mismatch for tenant=${entry.tenant_id} period=${entry.period_start}..${entry.period_end}: expected ${expected}, recomputed ${computed}`,
    );
  }
  if (entry.row_count !== null && entry.row_count !== undefined && entry.row_count !== sorted.length) {
    errors.push(
      `row_count mismatch for tenant=${entry.tenant_id} period=${entry.period_start}..${entry.period_end}: manifest says ${entry.row_count}, bundle contains ${sorted.length}`,
    );
  }
  return { ok: errors.length === 0, errors, computed };
}

// ─── Public API ──────────────────────────────────────────────────────────────

export async function verifyBundle(file: File): Promise<VerificationReport> {
  const { metadata, rows, roots } = await loadBundle(file);
  const checks: CheckResult[] = [];

  const perTenant = new Map<string, BundleRow[]>();
  for (const row of rows) {
    const t = row.tenant_id ?? '?';
    if (!perTenant.has(t)) perTenant.set(t, []);
    perTenant.get(t)!.push(row);
  }

  for (const [tenantId, tenantRows] of perTenant) {
    const start = metadata.chain_starts?.[tenantId] ?? {
      expected_start_sequence: 1,
      expected_previous_hash: ZERO_HASH,
    };
    const { ok, errors } = checkChain(tenantRows, start);
    if (ok) {
      checks.push({
        status: 'pass',
        message: `Chain intact for tenant ${tenantId}`,
        detail: `${tenantRows.length} rows starting at seq ${start.expected_start_sequence}`,
      });
    } else {
      for (const e of errors) {
        checks.push({ status: 'fail', message: 'Chain check failed', detail: e });
      }
    }
  }

  for (const entry of roots) {
    const first = entry.first_sequence_number;
    const last = entry.last_sequence_number;
    const inPeriod = (perTenant.get(entry.tenant_id) ?? []).filter(
      (r) =>
        first !== null &&
        first !== undefined &&
        last !== null &&
        last !== undefined &&
        r.sequence_number >= first &&
        r.sequence_number <= last,
    );
    const { ok, errors, computed } = await checkMerkle(entry, inPeriod);
    if (ok) {
      checks.push({
        status: 'pass',
        message: `Merkle root matches for tenant ${entry.tenant_id}`,
        detail: `period ${entry.period_start}..${entry.period_end} (${inPeriod.length} rows) — root ${computed?.slice(0, 12)}…`,
      });
    } else {
      for (const e of errors) {
        checks.push({ status: 'fail', message: 'Merkle check failed', detail: e });
      }
    }
  }

  checks.push({
    status: 'info',
    message: 'Anchor signature check skipped',
    detail:
      'Anchor HMAC is a symmetric secret and is never shipped in the bundle. Merkle-root match against our Object-Lock-anchored S3 manifests is the binding integrity proof.',
  });

  const ok = checks.every((c) => c.status !== 'fail');
  return {
    ok,
    metadata,
    rowCount: rows.length,
    rootCount: roots.length,
    checks,
  };
}

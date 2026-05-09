// Heuristic mapping from runtime detection categories → candidate
// regulatory citations. Lets the violation feed surface the same chips
// the policy editor shows, without round-tripping the merged-pack rules
// for every row.

const PII_CATEGORY_TO_CITATIONS: Record<string, string[]> = {
  us_ssn: ['45 CFR §164.312(a)(1)', 'GDPR Art. 32'],
  ssn: ['45 CFR §164.312(a)(1)', 'GDPR Art. 32'],
  medical_record_number: ['45 CFR §164.312(a)(1)', '45 CFR §164.312(e)(1)'],
  diagnosis_code: ['45 CFR §164.312(a)(1)', '45 CFR §164.312(b)'],
  insurance_id: ['45 CFR §164.312(e)(1)'],
  credit_card_number: ['PCI DSS v4.0 Req. 3.4', 'PCI DSS v4.0 Req. 4.2'],
  cvv: ['PCI DSS v4.0 Req. 3.4'],
  magnetic_stripe: ['PCI DSS v4.0 Req. 3.4'],
  email: ['GDPR Art. 5', 'GDPR Art. 32'],
  phone_number: ['GDPR Art. 5'],
  ip_address: ['GDPR Art. 5'],
  credit_score: ['EU AI Act Art. 9', 'EU AI Act Art. 14'],
  criminal_record: ['EU AI Act Art. 9', 'EU AI Act Art. 14'],
  employment_record: ['EU AI Act Art. 9', 'EU AI Act Art. 14'],
};

const INJECTION_DEFAULT_CITATIONS = [
  'EU AI Act Art. 15',
  'NIST AI RMF Measure 2.7',
  'SOC 2 CC6.6',
];

export function citationsForViolation(opts: {
  piiCategories?: string[];
  injectionDetected?: boolean;
}): string[] {
  const out = new Set<string>();
  for (const cat of opts.piiCategories ?? []) {
    for (const c of PII_CATEGORY_TO_CITATIONS[cat] ?? []) {
      out.add(c);
    }
  }
  if (opts.injectionDetected) {
    for (const c of INJECTION_DEFAULT_CITATIONS) {
      out.add(c);
    }
  }
  return Array.from(out);
}

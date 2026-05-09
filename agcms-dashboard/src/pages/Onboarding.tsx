import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import {
  Building2,
  Check,
  ChevronRight,
  Loader2,
  ScrollText,
  Sparkles,
  Terminal,
} from 'lucide-react';
import {
  fetchOnboardingCatalog,
  fetchOnboardingState,
  submitTenantProfile,
  submitFrameworks,
  submitPolicyPacks,
  recordFirstCall,
  type OnboardingCatalog,
} from '../lib/api';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';

const STEPS = [
  { id: 1, label: 'Tenant profile', icon: Building2 },
  { id: 2, label: 'Compliance frameworks', icon: ScrollText },
  { id: 3, label: 'Policy packs', icon: Sparkles },
  { id: 4, label: 'First API call', icon: Terminal },
];

function StepHeader({ current }: { current: number }) {
  return (
    <div className="flex items-center gap-3 mb-8">
      {STEPS.map((step, idx) => {
        const done = current > step.id;
        const active = current === step.id;
        const Icon = step.icon;
        return (
          <div key={step.id} className="flex items-center gap-3">
            <div
              className={`flex items-center gap-2 px-3 py-1.5 rounded-md border ${
                active
                  ? 'border-accent bg-accent/10 text-accent'
                  : done
                  ? 'border-success/40 bg-success/10 text-success'
                  : 'border-border-subtle text-fg-muted'
              }`}
            >
              {done ? <Check size={14} /> : <Icon size={14} />}
              <span className="text-caption">{step.label}</span>
            </div>
            {idx < STEPS.length - 1 && (
              <ChevronRight size={14} className="text-fg-subtle" />
            )}
          </div>
        );
      })}
    </div>
  );
}

function TenantProfileStep({
  catalog,
  onDone,
}: {
  catalog: OnboardingCatalog;
  onDone: () => void;
}) {
  const qc = useQueryClient();
  const [industry, setIndustry] = useState(catalog.industries[0]);
  const [size, setSize] = useState(catalog.company_sizes[2] ?? catalog.company_sizes[0]);
  const [region, setRegion] = useState(catalog.regions[0]);

  const mutate = useMutation({
    mutationFn: () =>
      submitTenantProfile({ industry, company_size: size, region }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['onboarding-state'] });
      onDone();
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Tell us about your tenant</CardTitle>
        <CardDescription>
          We use these answers to pre-select the compliance frameworks you're
          likely to need on the next step.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <label className="block">
          <div className="text-caption text-fg-muted mb-1">Industry</div>
          <select
            className="w-full bg-bg-raised border border-border-subtle rounded-md px-3 py-2 text-caption text-fg-primary"
            value={industry}
            onChange={(e) => setIndustry(e.target.value)}
          >
            {catalog.industries.map((i) => (
              <option key={i} value={i}>
                {i}
              </option>
            ))}
          </select>
        </label>
        <label className="block">
          <div className="text-caption text-fg-muted mb-1">Company size</div>
          <select
            className="w-full bg-bg-raised border border-border-subtle rounded-md px-3 py-2 text-caption text-fg-primary"
            value={size}
            onChange={(e) => setSize(e.target.value)}
          >
            {catalog.company_sizes.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <label className="block">
          <div className="text-caption text-fg-muted mb-1">Primary region</div>
          <select
            className="w-full bg-bg-raised border border-border-subtle rounded-md px-3 py-2 text-caption text-fg-primary"
            value={region}
            onChange={(e) => setRegion(e.target.value)}
          >
            {catalog.regions.map((r) => (
              <option key={r} value={r}>
                {r.toUpperCase()}
              </option>
            ))}
          </select>
        </label>
        <div className="flex justify-end">
          <Button onClick={() => mutate.mutate()} disabled={mutate.isPending}>
            {mutate.isPending ? (
              <Loader2 size={14} className="animate-spin mr-2" />
            ) : null}
            Continue
          </Button>
        </div>
        {mutate.isError && (
          <div className="text-caption text-danger">
            {(mutate.error as Error).message}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function suggestedForIndustry(industry: string | undefined): string[] {
  // Lightweight client-side hint that pre-selects likely frameworks to
  // shorten the wizard. Final selection is still submitted by the user.
  if (!industry) return [];
  if (industry === 'healthcare') return ['HIPAA', 'SOC_2'];
  if (industry === 'banking' || industry === 'insurance') return ['PCI_DSS', 'SOC_2'];
  if (industry === 'tech') return ['SOC_2', 'GDPR'];
  return ['SOC_2'];
}

function FrameworksStep({
  catalog,
  defaults,
  onDone,
}: {
  catalog: OnboardingCatalog;
  defaults: string[];
  onDone: (suggestedPacks: string[]) => void;
}) {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<string[]>(
    defaults.length > 0 ? defaults : [catalog.frameworks[0]?.id].filter(Boolean) as string[]
  );

  const mutate = useMutation({
    mutationFn: () => submitFrameworks(selected),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['onboarding-state'] });
      onDone(res.suggested_packs);
    },
  });

  const toggle = (id: string) =>
    setSelected((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));

  return (
    <Card>
      <CardHeader>
        <CardTitle>Which frameworks must your AI traffic satisfy?</CardTitle>
        <CardDescription>
          Pick every framework that applies. We'll map every violation and audit
          entry back to the specific article in each framework.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          {catalog.frameworks.map((f) => {
            const on = selected.includes(f.id);
            return (
              <button
                key={f.id}
                type="button"
                onClick={() => toggle(f.id)}
                className={`w-full text-left flex items-center justify-between px-4 py-3 rounded-md border ${
                  on
                    ? 'border-accent bg-accent/10'
                    : 'border-border-subtle hover:bg-bg-raised'
                }`}
              >
                <div>
                  <div className="text-caption font-medium text-fg-primary">{f.label}</div>
                  <a
                    href={f.citation_root}
                    target="_blank"
                    rel="noopener noreferrer"
                    onClick={(e) => e.stopPropagation()}
                    className="text-micro text-fg-muted hover:text-accent"
                  >
                    {f.citation_root}
                  </a>
                </div>
                <div
                  className={`w-4 h-4 rounded border ${
                    on ? 'bg-accent border-accent' : 'border-border-subtle'
                  }`}
                >
                  {on && <Check size={12} className="text-fg-onAccent m-0.5" />}
                </div>
              </button>
            );
          })}
        </div>
        <div className="flex justify-end">
          <Button
            onClick={() => mutate.mutate()}
            disabled={selected.length === 0 || mutate.isPending}
          >
            {mutate.isPending ? <Loader2 size={14} className="animate-spin mr-2" /> : null}
            Continue
          </Button>
        </div>
        {mutate.isError && (
          <div className="text-caption text-danger">
            {(mutate.error as Error).message}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function PolicyPacksStep({
  suggested,
  onDone,
}: {
  suggested: string[];
  onDone: () => void;
}) {
  const qc = useQueryClient();
  const [packs, setPacks] = useState<string[]>(suggested);

  const mutate = useMutation({
    mutationFn: () => submitPolicyPacks(packs),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['onboarding-state'] });
      onDone();
    },
  });

  const toggle = (p: string) =>
    setPacks((prev) => (prev.includes(p) ? prev.filter((x) => x !== p) : [...prev, p]));

  return (
    <Card>
      <CardHeader>
        <CardTitle>Policy packs</CardTitle>
        <CardDescription>
          We pre-selected the packs that satisfy your frameworks. Uncheck any you
          want to customise later — you can always load them from the Policy page.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-2">
          {suggested.map((p) => (
            <Badge
              key={p}
              variant={packs.includes(p) ? 'accent' : 'subtle'}
              className="cursor-pointer"
              onClick={() => toggle(p)}
            >
              {p}
            </Badge>
          ))}
        </div>
        <div className="flex justify-end">
          <Button
            onClick={() => mutate.mutate()}
            disabled={packs.length === 0 || mutate.isPending}
          >
            {mutate.isPending ? <Loader2 size={14} className="animate-spin mr-2" /> : null}
            Continue
          </Button>
        </div>
        {mutate.isError && (
          <div className="text-caption text-danger">
            {(mutate.error as Error).message}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function FirstCallStep({ onDone }: { onDone: () => void }) {
  const qc = useQueryClient();
  const [interactionId, setInteractionId] = useState('');
  const mutate = useMutation({
    mutationFn: (id: string) => recordFirstCall(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['onboarding-state'] });
      onDone();
    },
  });

  const curl = useMemo(
    () =>
      `curl -X POST https://your-agcms-host/v1/chat/completions \\\n` +
      `  -H "Authorization: Bearer $AGCMS_API_KEY" \\\n` +
      `  -H "Content-Type: application/json" \\\n` +
      `  -d '{"model":"llama-3.3-70b-versatile","messages":[{"role":"user","content":"Hello from AGCMS"}]}'`,
    []
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle>Make your first governed call</CardTitle>
        <CardDescription>
          Copy the request below, fire it at AGCMS, then paste the returned
          <code className="mx-1 font-mono text-accent">X-AGCMS-Interaction-ID</code>
          to finish onboarding.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <pre className="font-mono text-micro text-fg-secondary bg-bg-raised border border-border-subtle rounded-md p-4 overflow-x-auto whitespace-pre">
{curl}
        </pre>
        <label className="block">
          <div className="text-caption text-fg-muted mb-1">Interaction ID</div>
          <input
            className="w-full bg-bg-raised border border-border-subtle rounded-md px-3 py-2 text-caption text-fg-primary font-mono"
            placeholder="e.g. 5e6ab2e4-…"
            value={interactionId}
            onChange={(e) => setInteractionId(e.target.value.trim())}
          />
        </label>
        <div className="flex justify-end">
          <Button
            disabled={interactionId.length < 8 || mutate.isPending}
            onClick={() => mutate.mutate(interactionId)}
          >
            {mutate.isPending ? <Loader2 size={14} className="animate-spin mr-2" /> : null}
            Finish
          </Button>
        </div>
        {mutate.isError && (
          <div className="text-caption text-danger">
            {(mutate.error as Error).message}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function Onboarding() {
  const navigate = useNavigate();
  const { data: stateData, isLoading: stateLoading } = useQuery({
    queryKey: ['onboarding-state'],
    queryFn: fetchOnboardingState,
  });
  const { data: catalog, isLoading: catalogLoading } = useQuery({
    queryKey: ['onboarding-catalog'],
    queryFn: fetchOnboardingCatalog,
  });

  const [step, setStep] = useState(1);
  const [suggestedPacks, setSuggestedPacks] = useState<string[]>([]);

  // Resume from wherever the user left off last session.
  useEffect(() => {
    if (!stateData) return;
    const s = stateData.state;
    if (stateData.completed) {
      navigate('/', { replace: true });
      return;
    }
    if (!s.tenant_profile) setStep(1);
    else if (!s.frameworks) setStep(2);
    else if (!s.policy_packs) setStep(3);
    else setStep(4);

    if (s.suggested_packs && s.suggested_packs.length > 0) {
      setSuggestedPacks(s.suggested_packs);
    }
  }, [stateData, navigate]);

  if (stateLoading || catalogLoading || !catalog) {
    return (
      <div className="flex items-center justify-center h-64 text-fg-muted">
        <Loader2 size={20} className="animate-spin" />
      </div>
    );
  }

  const defaultFrameworks =
    stateData?.state.frameworks ??
    suggestedForIndustry(stateData?.state.tenant_profile?.industry);

  return (
    <div className="max-w-2xl mx-auto py-10">
      <div className="mb-8">
        <h1 className="text-h2 text-fg-primary">Welcome to AGCMS</h1>
        <p className="text-caption text-fg-muted mt-1">
          Four quick steps and you'll be watching live traffic through a tamper-evident audit trail.
        </p>
      </div>
      <StepHeader current={step} />

      {step === 1 && (
        <TenantProfileStep catalog={catalog} onDone={() => setStep(2)} />
      )}
      {step === 2 && (
        <FrameworksStep
          catalog={catalog}
          defaults={defaultFrameworks}
          onDone={(packs) => {
            setSuggestedPacks(packs);
            setStep(3);
          }}
        />
      )}
      {step === 3 && (
        <PolicyPacksStep
          suggested={
            suggestedPacks.length > 0
              ? suggestedPacks
              : stateData?.state.suggested_packs ?? []
          }
          onDone={() => setStep(4)}
        />
      )}
      {step === 4 && (
        <FirstCallStep onDone={() => navigate('/', { replace: true })} />
      )}
    </div>
  );
}

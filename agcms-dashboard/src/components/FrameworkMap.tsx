import { ExternalLink } from 'lucide-react';
import frameworks from '../lib/frameworks.json';
import { Badge } from './ui/badge';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from './ui/tooltip';
import { cn } from '../lib/cn';

type FrameworkEntry = {
  framework: string;
  title: string;
  text: string;
  url: string;
};

const FRAMEWORK_LIB = frameworks as Record<string, FrameworkEntry>;

const FRAMEWORK_LABEL: Record<string, string> = {
  HIPAA: 'HIPAA',
  GDPR: 'GDPR',
  EU_AI_ACT: 'EU AI Act',
  NIST_AI_RMF: 'NIST AI RMF',
  SOC_2: 'SOC 2',
  PCI_DSS: 'PCI DSS',
};

export function lookupCitation(id: string): FrameworkEntry | null {
  return FRAMEWORK_LIB[id] ?? null;
}

export function frameworkLabel(framework: string): string {
  return FRAMEWORK_LABEL[framework] ?? framework;
}

interface CitationChipProps {
  citationId: string;
  className?: string;
}

export function CitationChip({ citationId, className }: CitationChipProps) {
  const entry = lookupCitation(citationId);
  if (!entry) {
    return (
      <Badge variant="neutral" className={className} title="Unknown citation">
        {citationId}
      </Badge>
    );
  }
  return (
    <TooltipProvider delayDuration={120}>
      <Tooltip>
        <TooltipTrigger asChild>
          <a
            href={entry.url}
            target="_blank"
            rel="noopener noreferrer"
            className={cn('inline-flex no-underline', className)}
            data-testid={`citation-chip-${citationId}`}
          >
            <Badge variant="info" className="cursor-help">
              {citationId}
              <ExternalLink className="ml-1 h-3 w-3 opacity-70" />
            </Badge>
          </a>
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-sm whitespace-normal text-left">
          <div className="text-label font-medium text-fg-primary">
            {frameworkLabel(entry.framework)} — {entry.title}
          </div>
          <p className="mt-1 text-micro leading-snug text-fg-secondary">{entry.text}</p>
          <div className="mt-2 text-micro text-accent-bright">Click to open source ↗</div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

interface FrameworkMapProps {
  citations: string[];
  className?: string;
  emptyHint?: string;
}

export function FrameworkMap({ citations, className, emptyHint }: FrameworkMapProps) {
  if (!citations || citations.length === 0) {
    return emptyHint ? (
      <span className={cn('text-micro text-fg-muted', className)}>{emptyHint}</span>
    ) : null;
  }
  return (
    <div className={cn('flex flex-wrap gap-1.5', className)}>
      {citations.map((c) => (
        <CitationChip key={c} citationId={c} />
      ))}
    </div>
  );
}

export function FrameworkSummary({ frameworks: frameworkList }: { frameworks: string[] }) {
  if (!frameworkList || frameworkList.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1.5">
      {frameworkList.map((f) => (
        <Badge key={f} variant="accent">
          {frameworkLabel(f)}
        </Badge>
      ))}
    </div>
  );
}

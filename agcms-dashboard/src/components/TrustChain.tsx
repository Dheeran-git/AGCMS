import { cn } from '../lib/cn';

/**
 * TrustChain — visual motif of the per-tenant hash chain.
 *
 * Reads as a row of block nodes connected by hairline edges. Verified blocks
 * show a green inset glow; pending blocks show only the default border.
 * Reusable across Audit and Trust Center.
 *
 * Reference: design-system/preview/trust-chain.html.
 */

export type TrustBlock = {
  /** Display label rendered at the centre of the node, e.g. "#04827". */
  label: string;
  /** Short mono caption rendered under the block, e.g. "a8f3…2b1". */
  caption?: string;
  /** Whether this block has been HMAC-verified vs still pending. */
  verified?: boolean;
};

interface TrustChainProps {
  blocks: TrustBlock[];
  legend?: string;
  className?: string;
}

export function TrustChain({
  blocks,
  legend = 'HMAC-SHA256 · prev_sig included',
  className,
}: TrustChainProps) {
  const verifiedCount = blocks.filter((b) => b.verified).length;
  const pendingCount = blocks.length - verifiedCount;

  return (
    <div className={cn('rounded-lg border border-border bg-translucent-1 p-5', className)}>
      <div className="text-micro uppercase tracking-wider text-fg-muted mb-1">
        Trust motif · per-tenant hash chain
      </div>

      <div className="flex items-center gap-0 py-4">
        {blocks.map((block, idx) => (
          <ChainSegment key={`${block.label}-${idx}`} block={block} hasLink={idx < blocks.length - 1} />
        ))}
      </div>

      <div className="flex justify-between items-center pt-2.5 border-t border-border-subtle">
        <span className="font-mono text-micro text-fg-muted">{legend}</span>
        <span
          className={cn(
            'inline-flex items-center px-2.5 py-0.5 rounded-full',
            'text-micro font-[510] border whitespace-nowrap',
            'bg-status-success-soft text-status-success border-status-success/30',
          )}
        >
          {verifiedCount} verified
          {pendingCount > 0 && ` · ${pendingCount} pending`}
        </span>
      </div>
    </div>
  );
}

function ChainSegment({ block, hasLink }: { block: TrustBlock; hasLink: boolean }) {
  return (
    <>
      <div className="flex-1 flex flex-col items-center gap-1.5">
        <div
          className={cn(
            'relative w-16 h-16 rounded-lg flex items-center justify-center',
            'bg-translucent-1 font-mono text-[11px] leading-[14px] font-[500] text-fg-secondary',
            block.verified
              ? 'border border-status-success/40 shadow-[inset_0_0_0_1px_rgba(16,185,129,0.4)]'
              : 'border border-border',
          )}
        >
          {block.label}
        </div>
        {block.caption && (
          <div className="font-mono text-[10px] leading-[14px] text-fg-subtle text-center">
            {block.caption}
          </div>
        )}
      </div>
      {hasLink && (
        <div
          className={cn(
            'flex-none w-7 h-px',
            block.verified
              ? 'bg-status-success/40'
              : 'bg-border-default',
          )}
          aria-hidden="true"
        />
      )}
    </>
  );
}

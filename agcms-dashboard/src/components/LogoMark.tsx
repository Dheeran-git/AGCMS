import { cn } from '../lib/cn';

interface LogoMarkProps {
  size?: number;
  className?: string;
  withGlow?: boolean;
}

/**
 * AGCMS logomark — Merkle tree.
 *
 * Root node above two leaves connected by hairline edges. References the
 * per-tenant hash chain that backs the audit-trail integrity claim. Reads
 * as a distinct triangular silhouette at every size.
 *
 * Geometry sourced from Claude Design handoff (`assets/logo.svg`).
 */
export function LogoMark({ size = 28, className, withGlow = true }: LogoMarkProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label="AGCMS"
      className={cn('shrink-0', withGlow && 'drop-shadow-[0_0_10px_rgba(113,112,255,0.35)]', className)}
    >
      <defs>
        <linearGradient id="agcms-bg" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#7f8bff" />
          <stop offset="55%" stopColor="#5e6ad2" />
          <stop offset="100%" stopColor="#3d47a8" />
        </linearGradient>
        <linearGradient id="agcms-sheen" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#ffffff" stopOpacity="0.22" />
          <stop offset="100%" stopColor="#ffffff" stopOpacity="0" />
        </linearGradient>
      </defs>

      {/* Squircle base — gradient indigo. */}
      <rect x="0" y="0" width="32" height="32" rx="8" fill="url(#agcms-bg)" />

      {/* Top-edge sheen for glass feel. */}
      <rect x="0" y="0" width="32" height="16" rx="8" fill="url(#agcms-sheen)" />

      {/* 1px hairline border, Linear-style. */}
      <rect
        x="0.5"
        y="0.5"
        width="31"
        height="31"
        rx="7.5"
        fill="none"
        stroke="#ffffff"
        strokeOpacity="0.18"
      />

      {/* Hairline edges connecting root to two leaves. */}
      <path
        d="M16 11 L9 21 M16 11 L23 21"
        stroke="#ffffff"
        strokeOpacity="0.55"
        strokeWidth="1.2"
        strokeLinecap="round"
      />

      {/* Root node (top-center). */}
      <rect x="13" y="7" width="6" height="6" rx="1.4" fill="#ffffff" />

      {/* Leaf nodes (bottom-left, bottom-right). */}
      <rect x="6" y="19" width="6" height="6" rx="1.4" fill="#ffffff" fillOpacity="0.86" />
      <rect x="20" y="19" width="6" height="6" rx="1.4" fill="#ffffff" fillOpacity="0.86" />
    </svg>
  );
}

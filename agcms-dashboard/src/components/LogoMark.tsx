import { cn } from '../lib/cn';

interface LogoMarkProps {
  size?: number;
  className?: string;
  withGlow?: boolean;
}

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
        <linearGradient id="agcms-stroke" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#ffffff" stopOpacity="0.98" />
          <stop offset="100%" stopColor="#dfe3ff" stopOpacity="0.92" />
        </linearGradient>
      </defs>

      {/* Squircle base */}
      <rect x="0" y="0" width="32" height="32" rx="8" fill="url(#agcms-bg)" />

      {/* Subtle top-edge sheen for glass feel */}
      <rect x="0" y="0" width="32" height="16" rx="8" fill="url(#agcms-sheen)" />

      {/* Inner hairline border — Linear-style 1px white border */}
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

      {/* Custom-drawn A: two strokes meeting at a peak + slim crossbar.
          Slightly asymmetric peak angle to read as a branded mark, not a font glyph. */}
      <path
        d="M8.6 23 L15.1 9.2 Q15.6 8.2 16.4 8.2 Q17.2 8.2 17.7 9.2 L24.2 23"
        stroke="url(#agcms-stroke)"
        strokeWidth="2.1"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
      <path
        d="M11.8 17.8 L21 17.8"
        stroke="url(#agcms-stroke)"
        strokeWidth="1.85"
        strokeLinecap="round"
      />
    </svg>
  );
}

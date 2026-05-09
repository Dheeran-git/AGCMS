// Linear-inspired chart palette. Hex values mirror the design tokens in tokens.css
// so they work everywhere Recharts is used (SVG attributes can't resolve CSS vars).
export const chartColors = {
  primary:   '#7170ff',  // accent-bright
  primaryAlt:'#5e6ad2',  // accent
  success:   '#10b981',  // status-success
  warning:   '#f59e0b',  // status-warning
  danger:    '#ef4444',  // status-danger
  info:      '#7170ff',
  muted:     '#8a8f98',  // fg-muted
  subtle:    '#62666d',  // fg-subtle
  grid:      'rgba(255,255,255,0.05)',
  axis:      'rgba(255,255,255,0.08)',
  surface:   '#191a1b',
} as const;

// Gradient stop helpers for AreaChart fills
export function gradientStops(hex: string, topOpacity = 0.35, bottomOpacity = 0) {
  return [
    { offset: '0%',   stopColor: hex, stopOpacity: topOpacity },
    { offset: '100%', stopColor: hex, stopOpacity: bottomOpacity },
  ];
}

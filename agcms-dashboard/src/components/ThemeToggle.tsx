import { Moon, Sun } from 'lucide-react';
import { useThemeStore } from '../stores/theme';
import { cn } from '../lib/cn';

export function ThemeToggle({ className }: { className?: string }) {
  const { theme, toggleTheme } = useThemeStore();
  const isLight = theme === 'light';

  return (
    <button
      onClick={toggleTheme}
      aria-label={isLight ? 'Switch to dark mode' : 'Switch to light mode'}
      title={isLight ? 'Dark mode' : 'Light mode'}
      className={cn(
        'relative inline-flex items-center h-7 w-[52px] rounded-full shrink-0',
        'border border-border-default',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-bright',
        'cursor-pointer select-none',
        className
      )}
      style={{ background: 'var(--toggle-track)' }}
    >
      {/* Track glow when light */}
      <span
        className={cn(
          'absolute inset-0 rounded-full transition-opacity duration-300',
          isLight ? 'opacity-100' : 'opacity-0'
        )}
        style={{
          background:
            'linear-gradient(135deg, rgba(245,158,11,0.18) 0%, rgba(79,93,199,0.12) 100%)',
        }}
        aria-hidden="true"
      />

      {/* Icons — sun & moon pinned to each side of the track */}
      <span
        className="absolute left-[6px] flex items-center justify-center pointer-events-none"
        aria-hidden="true"
      >
        <Sun
          className={cn(
            'h-3 w-3 transition-all duration-300',
            isLight
              ? 'opacity-100 scale-100'
              : 'opacity-0 scale-75'
          )}
          style={{ color: 'var(--toggle-icon-sun)' }}
        />
      </span>
      <span
        className="absolute right-[6px] flex items-center justify-center pointer-events-none"
        aria-hidden="true"
      >
        <Moon
          className={cn(
            'h-3 w-3 transition-all duration-300',
            !isLight
              ? 'opacity-100 scale-100'
              : 'opacity-0 scale-75'
          )}
          style={{ color: 'var(--toggle-icon-moon)' }}
        />
      </span>

      {/* Sliding knob */}
      <span
        className={cn(
          'absolute top-[3px] h-5 w-5 rounded-full shadow-md',
          'transition-transform duration-300 ease-[cubic-bezier(0.34,1.56,0.64,1)]',
          isLight ? 'translate-x-[28px]' : 'translate-x-[3px]'
        )}
        style={{
          background: 'var(--toggle-knob)',
          boxShadow: isLight
            ? '0 1px 4px rgba(0,0,0,0.18), 0 0 0 1px rgba(0,0,0,0.06)'
            : '0 1px 4px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.06)',
        }}
        aria-hidden="true"
      />
    </button>
  );
}

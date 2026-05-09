import { forwardRef, type InputHTMLAttributes } from 'react';
import { cn } from '../../lib/cn';

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        'h-9 w-full rounded-md border border-border bg-translucent-1 px-3 text-caption text-fg-primary placeholder:text-fg-muted',
        'transition-colors duration-100',
        'focus:outline-none focus:border-accent-bright focus:shadow-focus',
        'disabled:opacity-50 disabled:pointer-events-none',
        className
      )}
      {...props}
    />
  )
);
Input.displayName = 'Input';

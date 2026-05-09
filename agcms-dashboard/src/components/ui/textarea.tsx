import { forwardRef, type TextareaHTMLAttributes } from 'react';
import { cn } from '../../lib/cn';

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(
  ({ className, ...props }, ref) => (
    <textarea
      ref={ref}
      className={cn(
        'w-full rounded-md border border-border bg-translucent-1 px-3 py-2.5 text-caption text-fg-primary placeholder:text-fg-muted',
        'transition-colors duration-100 resize-y',
        'focus:outline-none focus:border-accent-bright focus:shadow-focus',
        'disabled:opacity-50 disabled:pointer-events-none',
        className
      )}
      {...props}
    />
  )
);
Textarea.displayName = 'Textarea';

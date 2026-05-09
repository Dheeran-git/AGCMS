import { type HTMLAttributes } from 'react';
import { cn } from '../../lib/cn';

export function Kbd({ className, ...props }: HTMLAttributes<HTMLElement>) {
  return (
    <kbd
      className={cn(
        'inline-flex items-center justify-center min-w-[18px] h-[18px] px-1 rounded',
        'bg-translucent-2 border border-border-subtle',
        'text-micro text-fg-muted font-mono',
        className
      )}
      {...props}
    />
  );
}

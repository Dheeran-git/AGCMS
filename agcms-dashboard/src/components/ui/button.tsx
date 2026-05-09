import { forwardRef, type ButtonHTMLAttributes } from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { Slot } from '@radix-ui/react-slot';
import { cn } from '../../lib/cn';

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-1.5 select-none whitespace-nowrap transition-colors duration-100 disabled:opacity-50 disabled:pointer-events-none focus-visible:outline-none focus-visible:shadow-focus',
  {
    variants: {
      variant: {
        primary:
          'bg-accent text-white hover:bg-accent-hover active:bg-accent shadow-elev-1',
        ghost:
          'bg-translucent-1 text-fg-secondary hover:bg-translucent-2 hover:text-fg-primary border border-border',
        subtle:
          'bg-translucent-2 text-fg-secondary hover:bg-translucent-3 hover:text-fg-primary',
        outline:
          'bg-transparent text-fg-secondary hover:bg-translucent-1 hover:text-fg-primary border border-border',
        icon:
          'bg-translucent-1 text-fg-primary border border-border hover:bg-translucent-2 rounded-full',
        pill:
          'bg-transparent text-fg-secondary hover:bg-translucent-1 border border-[#23252a] rounded-full',
        danger:
          'bg-status-danger-soft text-status-danger hover:bg-status-danger/20 border border-status-danger/30',
        success:
          'bg-status-success-soft text-status-success hover:bg-status-success/20 border border-status-success/30',
        link:
          'bg-transparent text-accent-bright hover:text-accent-hover underline-offset-4 hover:underline',
        bare:
          'bg-transparent text-fg-muted hover:text-fg-primary',
      },
      size: {
        sm: 'h-7 px-2.5 text-label rounded-md',
        md: 'h-9 px-4 text-caption rounded-md',
        lg: 'h-11 px-5 text-body-emph rounded-md',
        icon: 'h-9 w-9 rounded-full',
        'icon-sm': 'h-7 w-7 rounded-full',
      },
    },
    defaultVariants: {
      variant: 'ghost',
      size: 'md',
    },
  }
);

export interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : 'button';
    return (
      <Comp ref={ref} className={cn(buttonVariants({ variant, size }), className)} {...props} />
    );
  }
);
Button.displayName = 'Button';

export { buttonVariants };

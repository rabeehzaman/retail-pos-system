// shadcn/ui components for React without JSX
// Using React.createElement for compatibility

const { useState, useEffect, useMemo, useRef } = React;

// Utility functions (inlined to avoid import issues)
function cn(...inputs) {
  const classes = [];
  for (const input of inputs) {
    if (input) {
      if (typeof input === 'string') {
        classes.push(input);
      }
    }
  }
  return classes.join(' ');
}

function cva(base, config = {}) {
  return function(props = {}) {
    let classes = base;
    
    if (config.variants) {
      for (const [key, value] of Object.entries(props)) {
        if (config.variants[key] && config.variants[key][value]) {
          classes += ' ' + config.variants[key][value];
        }
      }
    }
    
    // Apply default variants if not specified
    if (config.defaultVariants) {
      for (const [key, value] of Object.entries(config.defaultVariants)) {
        if (!props.hasOwnProperty(key)) {
          if (config.variants[key] && config.variants[key][value]) {
            classes += ' ' + config.variants[key][value];
          }
        }
      }
    }
    
    return classes;
  };
}

// Button Component (shadcn)
const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-all disabled:pointer-events-none disabled:opacity-50 outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground shadow hover:bg-primary/90",
        destructive: "bg-destructive text-destructive-foreground shadow-sm hover:bg-destructive/90",
        outline: "border border-input bg-background shadow-sm hover:bg-accent hover:text-accent-foreground",
        secondary: "bg-secondary text-secondary-foreground shadow-sm hover:bg-secondary/80",
        ghost: "hover:bg-accent hover:text-accent-foreground",
        link: "text-primary underline-offset-4 hover:underline",
      },
      size: {
        default: "h-9 px-4 py-2",
        sm: "h-8 rounded-md px-3 text-xs",
        lg: "h-10 rounded-md px-8",
        icon: "h-9 w-9",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
);

function Button({ className, variant, size, asChild = false, ...props }) {
  const Comp = asChild ? 'span' : 'button';
  
  return React.createElement(Comp, {
    className: cn(buttonVariants({ variant, size }), className),
    ...props
  });
}

// Input Component (shadcn)
function Input({ className, type = "text", ...props }) {
  return React.createElement('input', {
    type,
    className: cn(
      "flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50",
      className
    ),
    ...props
  });
}

// Card Components (shadcn)
function Card({ className, ...props }) {
  return React.createElement('div', {
    className: cn("rounded-xl border bg-card text-card-foreground shadow", className),
    ...props
  });
}

function CardHeader({ className, ...props }) {
  return React.createElement('div', {
    className: cn("flex flex-col space-y-1.5 p-6", className),
    ...props
  });
}

function CardTitle({ className, ...props }) {
  return React.createElement('h3', {
    className: cn("font-semibold leading-none tracking-tight", className),
    ...props
  });
}

function CardDescription({ className, ...props }) {
  return React.createElement('p', {
    className: cn("text-sm text-muted-foreground", className),
    ...props
  });
}

function CardContent({ className, ...props }) {
  return React.createElement('div', {
    className: cn("p-6 pt-0", className),
    ...props
  });
}

function CardFooter({ className, ...props }) {
  return React.createElement('div', {
    className: cn("flex items-center p-6 pt-0", className),
    ...props
  });
}

// Badge Component
function Badge({ className, variant = "default", ...props }) {
  const variants = {
    default: "border-transparent bg-primary text-primary-foreground shadow hover:bg-primary/80",
    secondary: "border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80",
    destructive: "border-transparent bg-destructive text-destructive-foreground shadow hover:bg-destructive/80",
    outline: "text-foreground",
  };

  return React.createElement('div', {
    className: cn(
      "inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
      variants[variant],
      className
    ),
    ...props
  }, props.children);
}

// Separator Component
function Separator({ className, orientation = "horizontal", ...props }) {
  return React.createElement('div', {
    className: cn(
      "shrink-0 bg-border",
      orientation === "horizontal" ? "h-[1px] w-full" : "h-full w-[1px]",
      className
    ),
    ...props
  });
}

// Enhanced Select components (simplified for this implementation)
function Select({ children, value, onValueChange }) {
  return React.createElement('select', {
    value,
    onChange: (e) => onValueChange && onValueChange(e.target.value),
    className: "flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
  }, children);
}

function SelectOption({ value, children }) {
  return React.createElement('option', { value }, children);
}

// Dialog components (simplified implementation)
function Dialog({ open, onOpenChange, children }) {
  if (!open) return null;
  
  return React.createElement('div', {
    className: "fixed inset-0 z-50 flex items-center justify-center",
    onClick: () => onOpenChange && onOpenChange(false)
  },
    React.createElement('div', {
      className: "fixed inset-0 bg-black/50"
    }),
    React.createElement('div', {
      className: "relative z-50 bg-background p-6 shadow-lg rounded-lg border max-w-md w-full mx-4",
      onClick: (e) => e.stopPropagation()
    }, children)
  );
}

function DialogHeader({ children, className }) {
  return React.createElement('div', {
    className: cn("flex flex-col space-y-2 text-center sm:text-left", className)
  }, children);
}

function DialogTitle({ children, className }) {
  return React.createElement('h2', {
    className: cn("text-lg font-semibold", className)
  }, children);
}

function DialogDescription({ children, className }) {
  return React.createElement('p', {
    className: cn("text-sm text-muted-foreground", className)
  }, children);
}

function DialogContent({ children, className }) {
  return React.createElement('div', {
    className: cn("mt-4", className)
  }, children);
}

function DialogFooter({ children, className }) {
  return React.createElement('div', {
    className: cn("flex flex-col-reverse sm:flex-row sm:justify-end sm:space-x-2 mt-6", className)
  }, children);
}

// Table Components (shadcn)
function Table({ className, ...props }) {
  return React.createElement('div', {
    className: "relative w-full overflow-auto"
  },
    React.createElement('table', {
      className: cn("w-full caption-bottom text-sm", className),
      ...props
    })
  );
}

function TableHeader({ className, ...props }) {
  return React.createElement('thead', {
    className: cn("[&_tr]:border-b", className),
    ...props
  });
}

function TableBody({ className, ...props }) {
  return React.createElement('tbody', {
    className: cn("[&_tr:last-child]:border-0", className),
    ...props
  });
}

function TableRow({ className, ...props }) {
  return React.createElement('tr', {
    className: cn("border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted", className),
    ...props
  });
}

function TableHead({ className, ...props }) {
  return React.createElement('th', {
    className: cn("h-10 px-2 text-left align-middle font-medium text-muted-foreground [&:has([role=checkbox])]:pr-0 [&>[role=checkbox]]:translate-y-[2px]", className),
    ...props
  });
}

function TableCell({ className, ...props }) {
  return React.createElement('td', {
    className: cn("p-2 align-middle [&:has([role=checkbox])]:pr-0 [&>[role=checkbox]]:translate-y-[2px]", className),
    ...props
  });
}

// Loading Spinner Component
function LoadingSpinner({ className }) {
  return React.createElement('div', {
    className: cn("animate-spin rounded-full border-2 border-gray-300 border-t-gray-900 h-4 w-4", className)
  });
}

// Toast/Alert Component (simplified)
function Toast({ variant = "default", className, children, ...props }) {
  const variants = {
    default: "bg-background text-foreground border",
    destructive: "bg-destructive text-destructive-foreground border-destructive",
    success: "bg-green-50 text-green-900 border-green-200 dark:bg-green-900/20 dark:text-green-100",
  };

  return React.createElement('div', {
    className: cn(
      "fixed top-4 right-4 z-50 rounded-md border p-4 shadow-lg transition-all duration-300",
      variants[variant],
      className
    ),
    ...props
  }, children);
}

// Make all components available globally for the POSApp to use
window.cn = cn;
window.cva = cva;
window.Button = Button;
window.Card = Card;
window.CardHeader = CardHeader;
window.CardContent = CardContent;
window.CardTitle = CardTitle;
window.CardDescription = CardDescription;
window.CardFooter = CardFooter;
window.Input = Input;
window.Select = Select;
window.SelectItem = SelectOption;
window.Dialog = Dialog;
window.DialogContent = DialogContent;
window.DialogHeader = DialogHeader;
window.DialogTitle = DialogTitle;
window.DialogDescription = DialogDescription;
window.DialogFooter = DialogFooter;
window.Badge = Badge;
window.LoadingSpinner = LoadingSpinner;
window.Toast = Toast;
window.Separator = Separator;
window.Table = Table;
window.TableHeader = TableHeader;
window.TableBody = TableBody;
window.TableRow = TableRow;
window.TableHead = TableHead;
window.TableCell = TableCell;
window.SelectOption = SelectOption;
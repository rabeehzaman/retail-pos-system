// Utility functions for shadcn components
// cn function for combining class names with precedence

/**
 * Combines class names with proper precedence
 * @param {...(string | undefined | null | false)} inputs - Class name inputs
 * @returns {string} Combined class names
 */
export function cn(...inputs) {
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

/**
 * Creates variant classes using class-variance-authority pattern
 * @param {string} base - Base classes
 * @param {Object} config - Variant configuration
 * @returns {Function} Variant function
 */
export function cva(base, config = {}) {
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

// Helper to format currency (keeping existing logic)
export function formatCurrency(amount, currency = 'SAR') {
  return new Intl.NumberFormat("en-SA", { 
    style: "currency", 
    currency: currency 
  }).format(amount);
}
// Enhanced version with unit selection buttons
function createProductCard(item, addToCart, formatCurrency) {
  return React.createElement('div', {
    key: item.id,
    className: "flex flex-col p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-emerald-500 transition-all"
  },
    // Product info
    React.createElement('div', { className: "text-2xl mb-2 text-center" }, '📦'),
    React.createElement('div', { className: "text-sm font-medium text-center mb-1" }, item.name),
    item.sku && React.createElement('div', { className: "text-xs text-slate-500 text-center" }, item.sku),
    
    // Price display
    React.createElement('div', { className: "text-lg font-bold text-center mt-2" }, 
      `${formatCurrency(item.price)} / ${item.defaultUnit || 'PCS'}`
    ),
    item.hasConversion && React.createElement('div', { className: "text-xs text-slate-500 text-center" }, 
      `Carton: ${formatCurrency(item.cartonPrice)}`
    ),
    
    // Stock
    item.stock_on_hand !== undefined && 
      React.createElement('div', { className: "text-xs text-slate-500 text-center mt-1" }, 
        `Stock: ${item.stock_on_hand}`
      ),
    
    // Action buttons
    React.createElement('div', { className: "mt-3 space-y-2" },
      // Add piece button (default)
      React.createElement('button', {
        onClick: () => addToCart(item, item.hasConversion ? 'PCS' : null),
        className: "w-full py-2 px-3 bg-emerald-600 text-white text-sm rounded-lg hover:bg-emerald-700 transition-colors"
      }, 
        item.hasConversion ? 'Add Piece' : 'Add Item'
      ),
      
      // Add carton button (if conversion available)
      item.hasConversion && React.createElement('button', {
        onClick: () => addToCart(item, 'CTN'),
        className: "w-full py-2 px-3 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 transition-colors"
      }, 
        'Add Carton'
      )
    )
  );
}

// Export for use in main app
window.createProductCard = createProductCard;
# Quick Reference Guide - Retail POS with Zoho Books

## 🚀 Starting the System

### Backend
```bash
cd retail-pos-backend
npm start
# Runs on http://localhost:3001
```

### Frontend
```bash
cd retail-pos-frontend
python3 -m http.server 3002
# Access at http://localhost:3002
```

## 🔑 Key Features

### Unit Conversion
- **Automatic**: C50P → Shows as PCS with piece pricing
- **Supported Patterns**: C6P, C12P, C24P, C50P, C100P
- **Display**: Shows "1 PCS @ 5.00 SAR" instead of "0.02 C50P @ 250 SAR"

### Price Calculation
- Carton price from Zoho ÷ Pieces per carton = Piece price
- Example: 250 SAR (C50P) ÷ 50 = 5 SAR per piece

## 📊 Unit Conversion IDs

| Pattern | Conversion ID |
|---------|--------------|
| C12P | 9465000000009224 |
| C24P | 9465000000009248 |
| C50P | 9465000000009268 |
| C100P | 9465000000016005 |

## 🛠 Debug Commands (Browser Console)

```javascript
// View current cart
debugPOS.getCart()

// View all items with pricing
debugPOS.getItems()

// Test unit pattern
debugPOS.testUnitConversion('C50P')

// Simulate invoice
debugPOS.simulateInvoice()

// Clear cart
debugPOS.clearCart()
```

## 🔍 Troubleshooting

### Invoice shows wrong unit (CTN instead of PCS)
1. Check browser console for: `Added unit_conversion_id: xxx`
2. Verify secondary units configured in Zoho Books
3. Hard refresh browser: Ctrl+Shift+R

### Items not loading
1. Check authentication status
2. Click sync button (🔄)
3. Check backend console for errors

### Inactive items error
- Items are automatically filtered
- Only active items shown in POS

## 📁 Important Files

- **Backend**: `/retail-pos-backend/server.js`
- **Frontend**: `/retail-pos-frontend/POSApp.js`
- **Config**: `/retail-pos-backend/.env`
- **Tokens**: `/retail-pos-backend/tokens.json`

## 🌐 Zoho Configuration

- **Organization**: 150000163897
- **Region**: Saudi Arabia (zoho.sa)
- **Tax**: 15% VAT
- **Currency**: SAR

## ✅ Working Features

- ✅ OAuth authentication with token persistence
- ✅ Fetch and display products with piece pricing
- ✅ Unit conversion (C50P → PCS)
- ✅ Invoice creation with correct units
- ✅ Customer selection
- ✅ Inactive item filtering
- ✅ Dark mode UI

## 🚫 Known Limitations

- Unit conversion IDs must be manually mapped
- Secondary units must be configured in Zoho Books
- No offline mode

---
For detailed documentation, see UNIT_CONVERSION_DOCUMENTATION.md
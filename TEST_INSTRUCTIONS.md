# Testing Unit of Measure Implementation

## Setup
1. Make sure backend is running on port 3001
2. Open frontend at http://localhost:3000
3. Open browser console (F12) for debugging output

## Test Scenarios

### 1. Check Item Processing
After authentication, when items load, check console for:
```
========== FETCHING ITEMS ==========
[Item 1] Processing: TUNA AL MAWASEM
  - Stored Unit: C6P
  - Pieces per carton: 6
  - Carton price: 210 SAR
  - Piece price: 35.00 SAR
```

### 2. Test Adding Items to Cart

#### For items with conversion (C6P, C12P):
- Default "Add" button should add as pieces
- Price should show per piece (e.g., 35 SAR/PCS for tuna)
- Console should show:
```
[CART] Adding item to cart:
  Item: TUNA AL MAWASEM
  Selected unit: PCS
  Price: 35 SAR
```

#### For plain carton items (CTN):
- Should only show carton price
- No piece conversion available

### 3. Test Invoice Creation

Add items to cart and process payment. Check console for:
```
========== CREATING INVOICE ==========
[Line Item 1]
  - Quantity: 2
  - Unit: PCS
  - Rate: 35 SAR
  - Line total: 70.00 SAR
```

The invoice in Zoho should show:
- "2 PCS" not "0.333 CTN"
- Correct piece price

### 4. Debug Commands

In browser console:
```javascript
// View current cart
debugPOS.getCart()

// View all items with pricing
debugPOS.getItems()

// Test unit pattern
debugPOS.testUnitConversion('C12P')
// Output: {unit: "C12P", piecesPerCarton: 12, pattern: "C{number}P format"}

// Simulate invoice from current cart
debugPOS.simulateInvoice()

// Clear cart for testing
debugPOS.clearCart()
```

### 5. Verify in Zoho

After creating an invoice:
1. Go to Zoho Books web interface
2. Check the latest invoice
3. Verify line items show:
   - Correct units (PCS or CTN)
   - No fractional conversions
   - Correct prices per unit

## Expected Results

### Correct Display:
```
Invoice Line: 5 PCS @ 5.42 SAR = 27.10 SAR
Invoice Line: 1 CTN @ 65.00 SAR = 65.00 SAR
```

### Incorrect (Old) Display:
```
Invoice Line: 0.417 CTN @ 65.00 SAR = 27.10 SAR  ❌
```

## Troubleshooting

### Issue: Items show wrong price
- Check console for price calculation logs
- Verify `piecesPerCarton` is parsed correctly
- Check if Zoho price is for carton (should be)

### Issue: Invoice shows fractions
- Check if `unit` field is being passed in line_items
- Verify console shows "Unit added to line item: PCS"
- Check invoice request payload in console

### Issue: No conversion available
- Item unit must match pattern C{number}P
- Plain "CTN" has no piece conversion
- Check `hasConversion` flag in item data

## Manual Unit Testing

Test these specific items:
1. **TUNA AL MAWASEM (C6P)**: 210÷6 = 35 SAR/piece
2. **CATERPILLAR CANDY (C12P)**: 65÷12 = 5.42 SAR/piece
3. **SALT 50KG (CTN)**: No conversion, 20 SAR/carton only
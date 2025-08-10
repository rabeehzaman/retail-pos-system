# Zoho Books POS Unit Conversion Documentation

## Overview
This document explains how the POS system handles unit conversions between cartons and pieces when creating invoices in Zoho Books.

## The Problem
- Items in Zoho Books are stored with carton units (C50P, C100P, etc.)
- We need to sell individual pieces and show "PCS" in invoices
- Zoho requires a `unit_conversion_id` to use secondary units

## The Solution

### 1. Unit Pattern Recognition
The system recognizes unit patterns in the format `C{number}P`:
- C6P = Carton of 6 pieces
- C12P = Carton of 12 pieces
- C24P = Carton of 24 pieces
- C50P = Carton of 50 pieces
- C100P = Carton of 100 pieces

### 2. Price Calculation
When items are fetched from Zoho:
```javascript
// Zoho stores carton price
const cartonPrice = item.rate;
// Calculate piece price
const piecePrice = cartonPrice / piecesPerCarton;
```

### 3. Unit Conversion IDs
Each carton size has a specific `unit_conversion_id` in Zoho Books:

| Stored Unit | Pieces per Carton | Unit Conversion ID |
|------------|-------------------|-------------------|
| C12P | 12 | 9465000000009224 |
| C24P | 24 | 9465000000009248 |
| C50P | 50 | 9465000000009268 |
| C100P | 100 | 9465000000016005 |

### 4. Invoice Creation
When creating an invoice with pieces:
```javascript
{
  "item_id": "9465000000063506",
  "quantity": 5,
  "rate": 2.06,  // Piece price
  "unit": "PCS",
  "unit_conversion_id": "9465000000009268"  // Required for C50P items
}
```

## Implementation Details

### Backend (server.js)

1. **Item Processing** (`/api/items`):
   - Parses unit patterns to determine pieces per carton
   - Calculates piece prices from carton prices
   - Sets default unit to PCS for items with conversion

2. **Invoice Creation** (`/api/invoices`):
   - Accepts unit and unit_conversion_id from frontend
   - Passes these fields to Zoho Books API
   - Logs all transformations for debugging

### Frontend (POSApp.js)

1. **Cart Management**:
   - Stores both display unit (PCS) and stored unit (C50P)
   - Tracks piece prices separately from carton prices

2. **Invoice Preparation**:
   ```javascript
   const conversionIdMap = {
     'C12P': '9465000000009224',
     'C24P': '9465000000009248',
     'C50P': '9465000000009268',
     'C100P': '9465000000016005'
   };
   
   if (item.unit === 'PCS') {
     lineItem.unit = 'PCS';
     lineItem.unit_conversion_id = conversionIdMap[item.storedUnit];
   }
   ```

## Prerequisites in Zoho Books

1. **Secondary Units Configuration**:
   - Each item must have secondary units configured in Zoho Books
   - Primary unit: C50P (or respective carton unit)
   - Secondary unit: PCS
   - Conversion rate: 1 C50P = 50 PCS

2. **Organization Settings**:
   - Organization ID: 150000163897
   - Region: Saudi Arabia (zoho.sa)
   - Tax: 15% VAT

## Testing Guide

### Test Items
- **C50P Item**: 505 SARDINE (ID: 9465000000063506)
- **C100P Item**: 555 FRIED SARDIN ESCABECHE (ID: 9465000000063536)
- **C12P Item**: ABC sauces
- **C24P Item**: DATU PUTI products

### Verification Steps
1. Add item to cart - should show piece price
2. Check console for unit conversion logs
3. Process payment
4. Verify invoice in Zoho shows "PCS" not "C50P"

## Debugging

### Console Commands
```javascript
// View cart with units
debugPOS.getCart()

// Test unit conversion
debugPOS.testUnitConversion('C50P')

// Simulate invoice
debugPOS.simulateInvoice()
```

### Common Issues

1. **Invoice shows wrong unit**:
   - Check if unit_conversion_id is being sent
   - Verify secondary units are configured in Zoho
   - Ensure correct conversion ID for the pattern

2. **Wrong price calculation**:
   - Verify pieces per carton parsing
   - Check if Zoho price is for carton (should be)

3. **Browser caching**:
   - Hard refresh: Ctrl+Shift+R (Windows) or Cmd+Shift+R (Mac)
   - Clear cache if changes don't appear

## Adding New Unit Patterns

To add support for new unit patterns:

1. **Get the unit_conversion_id**:
   - Create an invoice manually in Zoho Books
   - Use browser DevTools to capture the API request
   - Find the unit_conversion_id for that unit

2. **Update the mapping**:
   ```javascript
   const conversionIdMap = {
     'C12P': '9465000000009224',
     'C24P': '9465000000009248',
     'C50P': '9465000000009268',
     'C100P': '9465000000016005',
     'C6P': 'new_id_here',  // Add new pattern
   };
   ```

## API Flow

1. **Fetch Items** → Parse units → Calculate prices → Return to frontend
2. **Add to Cart** → Store with PCS unit → Track piece price
3. **Create Invoice** → Map unit_conversion_id → Send to Zoho
4. **Zoho Response** → Displays PCS in invoice

## Important Notes

- The `unit_conversion_id` is **required** for secondary units to work
- Each carton size has its own unique conversion ID
- These IDs are specific to the organization and cannot be hardcoded universally
- Always test with actual Zoho Books to verify unit display

## Files Modified

1. `/retail-pos-backend/server.js`:
   - Added unit parsing logic
   - Enhanced invoice creation with unit_conversion_id support

2. `/retail-pos-frontend/POSApp.js`:
   - Added unit conversion ID mapping
   - Enhanced cart to track units properly

3. `/retail-pos-backend/uom-handler.js`:
   - Unit of measure handling utilities

## Environment Variables

Required in `.env`:
```
ZOHO_CLIENT_ID=your_client_id
ZOHO_CLIENT_SECRET=your_client_secret
ZOHO_ORGANIZATION_ID=150000163897
ZOHO_REDIRECT_URI=https://httpbin.org/anything
ZOHO_ACCOUNTS_URL=https://accounts.zoho.sa
ZOHO_BOOKS_API_URL=https://www.zohoapis.sa/books/v3
```

---

Last Updated: August 10, 2025
Status: ✅ Working - Unit conversion successfully implemented
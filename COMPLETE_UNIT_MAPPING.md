# Complete Unit Conversion Mapping

## Overview
This document contains the complete unit conversion mapping for the POS system integrated with Zoho Books. These conversion IDs are used to display proper units (like "PCS") in Zoho Books invoices instead of the stored unit codes (like "C50P").

## Complete Conversion Map

| Unit Name | Description | Conversion ID | Pieces per Unit |
|-----------|-------------|---------------|-----------------|
| PIECES | Individual pieces | 9465000000009224 | 1 |
| C3P | Carton of 3 pieces | 9465000000016009 | 3 |
| C4P | Carton of 4 pieces | 9465000000009276 | 4 |
| C5P | Carton of 5 pieces | 9465000000009284 | 5 |
| C6P | Carton of 6 pieces | 9465000000009236 | 6 |
| C8P | Carton of 8 pieces | 9465000000009228 | 8 |
| C10P | Carton of 10 pieces | 9465000000009232 | 10 |
| C12P | Carton of 12 pieces | 9465000000009224 | 12 |
| C15P | Carton of 15 pieces | 9465000000016001 | 15 |
| C16P | Carton of 16 pieces | 9465000000009264 | 16 |
| C18P | Carton of 18 pieces | 9465000000009260 | 18 |
| C20P | Carton of 20 pieces | 9465000000009240 | 20 |
| C24P | Carton of 24 pieces | 9465000000009248 | 24 |
| C25P | Carton of 25 pieces | 9465000000009256 | 25 |
| C26P | Carton of 26 pieces | 9465000000009288 | 26 |
| C30P | Carton of 30 pieces | 9465000000009252 | 30 |
| C32P | Carton of 32 pieces | 9465000000009296 | 32 |
| C35P | Carton of 35 pieces | 9465000000016027 | 35 |
| C36P | Carton of 36 pieces | 9465000000009280 | 36 |
| C40P | Carton of 40 pieces | 9465000000009300 | 40 |
| C45P | Carton of 45 pieces | 9465000000016031 | 45 |
| C48P | Carton of 48 pieces | 9465000000009292 | 48 |
| C50P | Carton of 50 pieces | 9465000000009268 | 50 |
| C60P | Carton of 60 pieces | 9465000000009244 | 60 |
| C72P | Carton of 72 pieces | 9465000000009272 | 72 |
| C80P | Carton of 80 pieces | 9465000000016035 | 80 |
| C100P | Carton of 100 pieces | 9465000000016005 | 100 |
| C140P | Carton of 140 pieces | 9465000000016013 | 140 |
| C150P | Carton of 150 pieces | 9465000000016017 | 150 |
| BAG(4) | Bag of 4 pieces | 9465000006156003 | 4 |
| BAG(8) | Bag of 8 pieces | 9465000000686132 | 8 |
| RAFTHA | Raftha unit | 9465000000366030 | Variable |
| OUTER | Outer box | 9465000000366098 | Variable |

## Special Cases

### CTN (Generic Carton)
- **No conversion ID** - Returns empty array from Zoho API
- Needs to be handled separately in code

### C3(RPT) (Carton 3 Repeat)
- Has **multiple conversions**:
  - To RAFTHA: Conversion ID `9465000000366030`, Rate: 0.3333
  - To OUTER: Conversion ID `9465000000366098`, Rate: 0.0416

## Implementation

### Backend (server.js)
```javascript
const UNIT_CONVERSION_MAP = {
    "PIECES": "9465000000009224",
    "C12P": "9465000000009224",
    // ... complete mapping above
};

function getUnitConversionId(unit) {
    if (!unit) return null;
    const conversionId = UNIT_CONVERSION_MAP[unit.toUpperCase()];
    return conversionId || null;
}
```

### Invoice Creation Logic
When creating invoices, the system:
1. Detects when a PCS unit is being used
2. Looks up the stored unit (e.g., C50P) 
3. Finds the corresponding conversion ID
4. Adds `unit_conversion_id` to the line item
5. Sends to Zoho Books with proper unit display

### Frontend Integration
```javascript
const lineItems = cart.map(item => ({
    item_id: item.id,
    quantity: item.qty,
    rate: item.price,
    unit: item.unit, // "PCS"
    stored_unit: item.storedUnit, // "C50P"
    tax_id: item.tax_id || ""
}));
```

## Testing

### Verification Steps
1. Add item with carton unit (e.g., C50P) to cart
2. Item should display as "PCS" in POS
3. Create invoice
4. Check Zoho Books invoice - should show "PCS" not "C50P"
5. Verify pricing is correct (piece price, not carton price)

### Console Debugging
The system logs detailed unit conversion information:
```
[UOM] Unit C50P -> Conversion ID: 9465000000009268
[Line Item 1] Auto-added conversion ID for C50P: 9465000000009268
```

## Important Notes

1. **Organization Specific**: These conversion IDs are specific to organization `150000163897`
2. **Secondary Units Required**: Items must have secondary units configured in Zoho Books
3. **Automatic Mapping**: The system automatically maps PCS sales to proper conversion IDs
4. **Fallback Handling**: If no conversion ID found, item uses original unit
5. **Case Insensitive**: Unit matching is case insensitive

## Files Modified

1. **`/retail-pos-backend/server.js`**:
   - Updated complete UNIT_CONVERSION_MAP with correct IDs
   - Enhanced invoice creation with auto-conversion ID mapping

2. **`/pos-frontend-modern/src/App.jsx`**:
   - Updated UNIT_CONVERSION_MAP with correct IDs
   - Added stored_unit to line items for backend lookup

3. **`/pos-frontend-modern/src/AppMobile.jsx`**:
   - Updated UNIT_CONVERSION_MAP with correct IDs for mobile app

4. **`/retail-pos-backend/uom-handler.js`**:
   - Updated complete conversion mapping in UOMHandler class
   - Enhanced formatInvoiceLineItem method

## Status
✅ **Fully Updated** - All unit conversion IDs have been corrected based on actual Zoho Books API responses for accurate unit display in invoices.

---
Last Updated: December 16, 2025  
Status: ✅ Complete - All unit conversions mapped with correct IDs
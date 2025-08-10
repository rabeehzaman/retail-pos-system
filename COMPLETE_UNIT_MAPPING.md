# Complete Unit Conversion Mapping

## Overview
This document contains the complete unit conversion mapping for the POS system integrated with Zoho Books. These conversion IDs are used to display proper units (like "PCS") in Zoho Books invoices instead of the stored unit codes (like "C50P").

## Complete Conversion Map

| Unit Name | Description | Conversion ID | Pieces per Unit |
|-----------|-------------|---------------|-----------------|
| PIECES | Individual pieces | 9465000000009224 | 1 |
| C3P | Carton of 3 pieces | 9465000001021006 | 3 |
| C4P | Carton of 4 pieces | 9465000001006988 | 4 |
| C5P | Carton of 5 pieces | 9465000001006992 | 5 |
| C6P | Carton of 6 pieces | 9465000001006968 | 6 |
| C8P | Carton of 8 pieces | 9465000001006964 | 8 |
| C10P | Carton of 10 pieces | 9465000001006966 | 10 |
| C12P | Carton of 12 pieces | 9465000001006319 | 12 |
| C15P | Carton of 15 pieces | 9465000001021002 | 15 |
| C16P | Carton of 16 pieces | 9465000001006982 | 16 |
| C18P | Carton of 18 pieces | 9465000001006980 | 18 |
| C20P | Carton of 20 pieces | 9465000001006970 | 20 |
| C24P | Carton of 24 pieces | 9465000001006974 | 24 |
| C25P | Carton of 25 pieces | 9465000001006978 | 25 |
| C26P | Carton of 26 pieces | 9465000001006994 | 26 |
| C30P | Carton of 30 pieces | 9465000001006976 | 30 |
| C32P | Carton of 32 pieces | 9465000001006998 | 32 |
| C35P | Carton of 35 pieces | 9465000001021014 | 35 |
| C36P | Carton of 36 pieces | 9465000001006990 | 36 |
| C40P | Carton of 40 pieces | 9465000001007000 | 40 |
| C45P | Carton of 45 pieces | 9465000001021018 | 45 |
| C48P | Carton of 48 pieces | 9465000001006996 | 48 |
| C50P | Carton of 50 pieces | 9465000001006984 | 50 |
| C60P | Carton of 60 pieces | 9465000001006972 | 60 |
| C72P | Carton of 72 pieces | 9465000001006986 | 72 |
| C80P | Carton of 80 pieces | 9465000001021020 | 80 |
| C100P | Carton of 100 pieces | 9465000001021004 | 100 |
| C140P | Carton of 140 pieces | 9465000001021008 | 140 |
| C150P | Carton of 150 pieces | 9465000001021010 | 150 |
| CTN | Generic carton | 9465000001021016 | Variable |
| BAG | Bag unit | 9465000001021024 | Variable |
| BAG(8) | Bag of 8 pieces | 9465000001021026 | 8 |
| TIN | Tin container | 9465000001023397 | Variable |
| OUTER | Outer box | 9465000000366098 | Variable |
| RAFTHA | Raftha unit | 9465000000366030 | Variable |
| C3(RPT) | Carton 3 repeat | 9465000001021022 | 3 |
| CANCELD14P | Cancelled 14P | 9465000001021012 | 14 |

## Implementation

### Backend (server.js)
```javascript
const UNIT_CONVERSION_MAP = {
    "PIECES": "9465000000009224",
    "C12P": "9465000001006319",
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
[UOM] Unit C50P -> Conversion ID: 9465000001006984
[Line Item 1] Auto-added conversion ID for C50P: 9465000001006984
```

## Important Notes

1. **Organization Specific**: These conversion IDs are specific to organization `150000163897`
2. **Secondary Units Required**: Items must have secondary units configured in Zoho Books
3. **Automatic Mapping**: The system automatically maps PCS sales to proper conversion IDs
4. **Fallback Handling**: If no conversion ID found, item uses original unit
5. **Case Insensitive**: Unit matching is case insensitive

## Files Modified

1. **`/retail-pos-backend/server.js`**:
   - Added complete UNIT_CONVERSION_MAP
   - Enhanced invoice creation with auto-conversion ID mapping

2. **`/pos-frontend-modern/src/App.jsx`**:
   - Added stored_unit to line items for backend lookup

3. **`/retail-pos-backend/uom-handler.js`**:
   - Added complete conversion mapping to UOMHandler class
   - Enhanced formatInvoiceLineItem method

## Status
✅ **Fully Implemented** - All 37 unit types now supported with proper conversion IDs for accurate unit display in Zoho Books invoices.

---
Last Updated: August 10, 2025  
Status: ✅ Complete - All unit conversions mapped and implemented
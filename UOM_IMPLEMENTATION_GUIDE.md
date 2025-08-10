# Unit of Measure (UOM) Implementation Guide

## Overview
This guide explains how to change and manage Units of Measure (UOM) in your POS system integrated with Zoho Books/Inventory.

## Methods to Change UOM

### 1. **Zoho Web Interface (Easiest)**
Configure units directly in Zoho:

1. **Enable Unit Conversion:**
   - Go to Zoho Inventory → Settings → Items → Units of Measurement
   - Click "Enable Unit Conversion"
   - Set Unit Precision (decimal places)

2. **Create Conversion Rates:**
   - Click on a unit → View Unit Conversions
   - Add conversion rates (e.g., 1 meter = 100 centimeters)

3. **Update Item Units:**
   - Go to Items → Edit Item
   - Change the Unit field
   - Save changes

### 2. **Via API (Programmatic)**

#### Available Endpoints:

```bash
# Get available units
GET http://localhost:3001/api/units

# Update item unit
PUT http://localhost:3001/api/items/{itemId}/unit
Body: { "unit": "kg" }

# Convert quantities
POST http://localhost:3001/api/units/convert
Body: {
  "quantity": 10,
  "fromUnit": "pieces",
  "toUnit": "cartons",
  "itemUnit": "C24PCS"
}
```

### 3. **In Your POS Frontend**

Add unit selection to your POS:

```javascript
// Example: Add unit selector to product
function ProductWithUnit({ item, onAddToCart }) {
  const [selectedUnit, setSelectedUnit] = useState('pieces');
  const [quantity, setQuantity] = useState(1);
  
  // Check if item has carton conversion
  const hasCartonInfo = item.unit && /C\d+P(?:CS)?/i.test(item.unit);
  
  const handleAddToCart = () => {
    onAddToCart({
      ...item,
      quantity,
      selectedUnit,
      displayUnit: selectedUnit === 'cartons' ? 'CTN' : 'PCS'
    });
  };
  
  return (
    <div>
      <h3>{item.name}</h3>
      {hasCartonInfo && (
        <select value={selectedUnit} onChange={e => setSelectedUnit(e.target.value)}>
          <option value="pieces">Pieces</option>
          <option value="cartons">Cartons</option>
        </select>
      )}
      <input type="number" value={quantity} onChange={e => setQuantity(e.target.value)} />
      <button onClick={handleAddToCart}>Add to Cart</button>
    </div>
  );
}
```

## Unit Format Convention

### Standard Format: `C{number}PCS`
- `C24PCS` = 1 Carton contains 24 Pieces
- `C12PCS` = 1 Carton contains 12 Pieces
- `C6P` = 1 Carton contains 6 Pieces (short form)

### Common Units in Zoho:
- `qty` - Quantity (default)
- `pcs` - Pieces
- `box` - Box
- `kg` - Kilogram
- `g` - Gram
- `l` - Liter
- `ml` - Milliliter
- `m` - Meter
- `cm` - Centimeter

## Implementation Examples

### Example 1: Update All Items to Use Pieces

```javascript
async function updateAllItemsToPieces() {
  const response = await fetch('http://localhost:3001/api/items');
  const { items } = await response.json();
  
  for (const item of items) {
    await fetch(`http://localhost:3001/api/items/${item.id}/unit`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ unit: 'pcs' })
    });
  }
}
```

### Example 2: Smart Unit Detection

```javascript
function detectOptimalUnit(item) {
  // If item name contains keywords, suggest units
  const name = item.name.toLowerCase();
  
  if (name.includes('water') || name.includes('juice')) return 'l';
  if (name.includes('chips') || name.includes('snack')) return 'pcs';
  if (name.includes('rice') || name.includes('flour')) return 'kg';
  if (name.includes('cable') || name.includes('wire')) return 'm';
  
  // Check existing unit format
  if (item.unit && /C\d+P/i.test(item.unit)) {
    return 'cartons'; // Has carton conversion
  }
  
  return 'qty'; // Default
}
```

### Example 3: Invoice with Unit Conversion

```javascript
async function createInvoiceWithUnits(cartItems) {
  const lineItems = cartItems.map(item => {
    const uomHandler = new UOMHandler();
    
    // Convert if using cartons
    if (item.selectedUnit === 'cartons' && item.unit) {
      const piecesPerCarton = uomHandler.getPiecesPerCarton(item.unit);
      return {
        item_id: item.id,
        quantity: item.quantity * piecesPerCarton, // Convert to pieces
        rate: item.price / piecesPerCarton, // Adjust price per piece
        description: `${item.quantity} Cartons (${item.quantity * piecesPerCarton} pieces)`
      };
    }
    
    return {
      item_id: item.id,
      quantity: item.quantity,
      rate: item.price,
      unit: item.selectedUnit || item.unit || 'qty'
    };
  });
  
  return await createInvoice({ line_items: lineItems });
}
```

## Testing UOM Changes

### Test the endpoints:

```bash
# 1. Check current item units
curl http://localhost:3001/api/items

# 2. Update an item's unit
curl -X PUT http://localhost:3001/api/items/YOUR_ITEM_ID/unit \
  -H "Content-Type: application/json" \
  -d '{"unit": "kg"}'

# 3. Test unit conversion
curl -X POST http://localhost:3001/api/units/convert \
  -H "Content-Type: application/json" \
  -d '{
    "quantity": 24,
    "fromUnit": "pieces",
    "toUnit": "cartons",
    "itemUnit": "C24PCS"
  }'
```

## Important Notes

1. **Plan Limitations**: Unit conversion feature may not be available in all Zoho plans
2. **Precision**: Once set, unit precision cannot be reduced
3. **API Limits**: Bulk updates count against your API rate limit (100 requests/minute)
4. **Sync**: Changes made via API reflect immediately in Zoho web interface
5. **Invoicing**: Zoho Books expects quantities in base units for accurate calculations

## Troubleshooting

### Issue: Unit not updating
- Check if item is part of a composite item
- Verify API permissions include item update scope
- Ensure unit exists in Zoho's unit settings

### Issue: Conversion not working
- Enable unit conversion in Zoho settings first
- Set up conversion rates between units
- Check unit format matches expected pattern

### Issue: Invoice shows wrong quantity
- Verify conversion calculation
- Check if Zoho expects base unit quantities
- Review item's default unit settings

## Next Steps

1. **Restart backend** to load UOM handler:
   ```bash
   # Kill current process and restart
   cd retail-pos-backend
   npm start
   ```

2. **Test unit endpoints** using the examples above

3. **Update frontend** to show unit selectors where needed

4. **Configure Zoho** unit settings for your specific needs

Need help? Check Zoho's unit conversion documentation:
https://www.zoho.com/inventory/help/settings/unit-conversion.html
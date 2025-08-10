# Unit Display in Zoho Books Invoices

## Current Behavior
When you sell items by pieces in the POS, the invoice in Zoho Books will show the original unit code (e.g., "C50P") instead of "PCS". This is because:

1. **Zoho Books Limitation**: Zoho Books displays the unit that's configured for the item in their system
2. **No Secondary Unit**: The items don't have secondary units configured in Zoho Books
3. **Unit Code Meaning**: 
   - C50P = Carton of 50 Pieces
   - C12P = Carton of 12 Pieces
   - C6P = Carton of 6 Pieces

## What's Working Correctly
- ✅ Prices are calculated correctly per piece
- ✅ Quantity shows as 1, 2, 3 (not 0.02, 0.04 fractions)
- ✅ Total amounts are correct
- ✅ POS displays "PCS" for user clarity

## Example
- POS Display: "1 PCS @ 5.00 SAR"
- Zoho Invoice: "1 C50P @ 5.00 SAR"
- Both represent the same thing: 1 piece at 5 SAR

## Permanent Solution (Requires Zoho Configuration)
To show "PCS" in Zoho invoices, you need to:

1. **Configure Secondary Units in Zoho Books**:
   - Go to Zoho Books > Settings > Preferences > Items
   - Enable "I sell this item in different units"
   - For each item with CxxP unit:
     - Set Primary Unit: C50P (or whatever the carton unit is)
     - Set Secondary Unit: PCS
     - Set Conversion: 1 C50P = 50 PCS

2. **Update the POS**:
   - Once secondary units are configured in Zoho
   - The POS can send "PCS" as the unit
   - Zoho will accept and display it correctly

## Current Workaround
- The invoice includes a note explaining that CxxP units represent individual pieces
- The cart in POS shows both the display unit (PCS) and Zoho unit (C50P) for clarity
- All calculations are correct despite the unit display

## Technical Details
The POS system:
1. Detects unit patterns (C6P, C12P, C50P, etc.)
2. Calculates piece prices from carton prices
3. Displays "PCS" in the UI for clarity
4. Sends the original Zoho unit in invoices (required by Zoho API)
5. Maintains correct pricing throughout

This is a display issue only - all financial calculations are correct.
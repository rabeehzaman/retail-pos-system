// UOM Handler for Retail POS
const axios = require('axios');

class UOMHandler {
    constructor(accessToken, organizationId, apiUrl) {
        this.accessToken = accessToken;
        this.organizationId = organizationId;
        this.apiUrl = apiUrl;
    }

    // Parse unit conversion info (C24PCS format)
    parseUnitInfo(unit) {
        if (!unit) return null;
        const match = unit.match(/C(\d+)P(?:CS)?/i);
        if (match) {
            return {
                type: 'carton',
                piecesPerCarton: parseInt(match[1]),
                display: `1 Carton = ${match[1]} Pieces`
            };
        }
        return null;
    }

    // Check if unit has conversion
    hasUnitConversion(unit) {
        return /C\d+P(?:CS)?/i.test(unit);
    }

    // Get pieces per carton
    getPiecesPerCarton(unit) {
        const info = this.parseUnitInfo(unit);
        return info ? info.piecesPerCarton : 1;
    }

    // Convert quantity between units
    convertQuantity(quantity, fromUnit, toUnit, itemUnit) {
        if (!this.hasUnitConversion(itemUnit)) {
            return quantity; // No conversion available
        }

        const piecesPerCarton = this.getPiecesPerCarton(itemUnit);

        if (fromUnit === 'pieces' && toUnit === 'cartons') {
            return quantity / piecesPerCarton;
        } else if (fromUnit === 'cartons' && toUnit === 'pieces') {
            return quantity * piecesPerCarton;
        }

        return quantity;
    }

    // Update item unit via API
    async updateItemUnit(itemId, newUnit) {
        try {
            const response = await axios.put(
                `${this.apiUrl}/items/${itemId}`,
                { unit: newUnit },
                {
                    headers: { 
                        'Authorization': `Zoho-oauthtoken ${this.accessToken}`,
                        'Content-Type': 'application/json'
                    },
                    params: { organization_id: this.organizationId }
                }
            );
            return { success: true, item: response.data.item };
        } catch (error) {
            console.error('Failed to update item unit:', error.response?.data || error);
            return { 
                success: false, 
                error: error.response?.data?.message || 'Failed to update unit' 
            };
        }
    }

    // Get available units from Zoho
    async getAvailableUnits() {
        try {
            // Note: This endpoint may vary based on your Zoho setup
            // You might need to use settings endpoint
            const response = await axios.get(
                `${this.apiUrl}/settings/units`,
                {
                    headers: { 
                        'Authorization': `Zoho-oauthtoken ${this.accessToken}`
                    },
                    params: { organization_id: this.organizationId }
                }
            );
            return response.data.units || [];
        } catch (error) {
            console.error('Failed to fetch units:', error);
            // Return default units if API doesn't support this
            return [
                { unit: 'qty', name: 'Quantity' },
                { unit: 'pcs', name: 'Pieces' },
                { unit: 'box', name: 'Box' },
                { unit: 'kg', name: 'Kilogram' },
                { unit: 'g', name: 'Gram' },
                { unit: 'l', name: 'Liter' },
                { unit: 'ml', name: 'Milliliter' },
                { unit: 'm', name: 'Meter' },
                { unit: 'cm', name: 'Centimeter' }
            ];
        }
    }

    // Create invoice with unit conversion
    formatInvoiceLineItem(item, quantity, selectedUnit) {
        const lineItem = {
            item_id: item.id,
            rate: item.price
        };

        // Apply conversion if needed
        if (selectedUnit && item.unit && this.hasUnitConversion(item.unit)) {
            const convertedQty = this.convertQuantity(
                quantity, 
                selectedUnit, 
                'pieces', // Zoho typically expects base unit
                item.unit
            );
            lineItem.quantity = convertedQty;
            lineItem.description = `${quantity} ${selectedUnit} (${convertedQty} pieces)`;
        } else {
            lineItem.quantity = quantity;
            lineItem.unit = selectedUnit || item.unit || 'qty';
        }

        return lineItem;
    }
}

module.exports = UOMHandler;
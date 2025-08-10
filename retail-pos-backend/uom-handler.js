// UOM Handler for Retail POS
const axios = require('axios');

class UOMHandler {
    constructor(accessToken, organizationId, apiUrl) {
        this.accessToken = accessToken;
        this.organizationId = organizationId;
        this.apiUrl = apiUrl;
        
        // Complete unit conversion mapping from Zoho Books
        this.UNIT_CONVERSION_MAP = {
            "PIECES": "9465000000009224",
            "C12P": "9465000001006319",
            "C8P": "9465000001006964",
            "C10P": "9465000001006966",
            "C6P": "9465000001006968",
            "C20P": "9465000001006970",
            "C60P": "9465000001006972",
            "C24P": "9465000001006974",
            "C30P": "9465000001006976",
            "C25P": "9465000001006978",
            "C18P": "9465000001006980",
            "C16P": "9465000001006982",
            "C50P": "9465000001006984",
            "C72P": "9465000001006986",
            "C4P": "9465000001006988",
            "C36P": "9465000001006990",
            "C5P": "9465000001006992",
            "C26P": "9465000001006994",
            "C48P": "9465000001006996",
            "C32P": "9465000001006998",
            "C40P": "9465000001007000",
            "C15P": "9465000001021002",
            "C100P": "9465000001021004",
            "C3P": "9465000001021006",
            "C140P": "9465000001021008",
            "C150P": "9465000001021010",
            "CANCELD14P": "9465000001021012",
            "C35P": "9465000001021014",
            "CTN": "9465000001021016",
            "C45P": "9465000001021018",
            "C80P": "9465000001021020",
            "C3(RPT)": "9465000001021022",
            "RAFTHA": "9465000000366030",
            "OUTER": "9465000000366098",
            "BAG": "9465000001021024",
            "BAG(8)": "9465000001021026",
            "TIN": "9465000001023397"
        };
    }

    // Get unit conversion ID
    getUnitConversionId(unit) {
        if (!unit) return null;
        return this.UNIT_CONVERSION_MAP[unit.toUpperCase()] || null;
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
            rate: item.price,
            quantity: quantity
        };

        // Add unit and conversion ID if needed
        if (selectedUnit) {
            lineItem.unit = selectedUnit;
            
            // If selling in pieces but item is stored in cartons, add conversion ID
            if (selectedUnit === 'PCS' && item.storedUnit) {
                const conversionId = this.getUnitConversionId(item.storedUnit);
                if (conversionId) {
                    lineItem.unit_conversion_id = conversionId;
                }
            }
        } else {
            lineItem.unit = item.unit || 'qty';
        }

        return lineItem;
    }
}

module.exports = UOMHandler;
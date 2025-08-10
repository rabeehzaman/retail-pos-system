const express = require('express');
const axios = require('axios');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
require('dotenv').config();
const UOMHandler = require('./uom-handler');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Token storage (similar to Transfer Order POS)
const tokenFile = path.join(__dirname, 'tokens.json');
let accessToken = null;
let refreshToken = null;
let tokenExpiresAt = null;

// Load tokens from environment variables or file (TransferOrderPOS pattern)
function loadTokens() {
    try {
        // First try to load from environment variables (for Railway/containers)
        if (process.env.ZOHO_ACCESS_TOKEN && process.env.ZOHO_REFRESH_TOKEN) {
            accessToken = process.env.ZOHO_ACCESS_TOKEN;
            refreshToken = process.env.ZOHO_REFRESH_TOKEN;
            // Load expiry time if available, otherwise set to 1 hour from now
            tokenExpiresAt = process.env.ZOHO_TOKEN_EXPIRES_AT 
                ? parseInt(process.env.ZOHO_TOKEN_EXPIRES_AT) 
                : Date.now() + (3600 * 1000);
            console.log('📦 Loaded tokens from environment variables (Railway mode)');
            if (tokenExpiresAt) {
                const expiresIn = Math.max(0, Math.floor((tokenExpiresAt - Date.now()) / 1000));
                console.log(`Token expires in ${expiresIn} seconds`);
            }
            return;
        }
        
        // Fallback: try to load from file
        if (fs.existsSync(tokenFile)) {
            const fileContent = fs.readFileSync(tokenFile, 'utf8').trim();
            if (fileContent) {
                const tokens = JSON.parse(fileContent);
                
                // Validate that all required tokens exist
                if (tokens.accessToken && tokens.refreshToken) {
                    accessToken = tokens.accessToken;
                    refreshToken = tokens.refreshToken;
                    tokenExpiresAt = tokens.expiresAt || null;
                    console.log('✅ Loaded saved tokens from file');
                    if (tokenExpiresAt) {
                        const expiresIn = Math.max(0, Math.floor((tokenExpiresAt - Date.now()) / 1000));
                        console.log(`Token expires in ${expiresIn} seconds`);
                    }
                    return;
                } else {
                    console.log('⚠️ Incomplete tokens found in file, clearing corrupted data');
                    clearTokens();
                }
            }
        }
        
        console.log('ℹ️  No saved tokens found - authentication required');
    } catch (error) {
        console.error('Error loading tokens:', error);
    }
}

// Save tokens to file
function saveTokens() {
    try {
        if (!accessToken || !refreshToken) {
            console.log('⚠️ Skipping save - missing required tokens');
            return;
        }
        
        const tokens = {
            accessToken,
            refreshToken,
            expiresAt: tokenExpiresAt,
            savedAt: new Date().toISOString()
        };
        fs.writeFileSync(tokenFile, JSON.stringify(tokens, null, 2));
        console.log('✅ Tokens saved to file');
    } catch (error) {
        console.error('⚠️ Could not save tokens to file:', error.message);
    }
}

// Clear tokens
function clearTokens() {
    try {
        if (fs.existsSync(tokenFile)) {
            fs.unlinkSync(tokenFile);
            console.log('✅ Tokens file deleted');
        }
    } catch (error) {
        console.error('⚠️ Could not delete tokens file:', error.message);
    }
}

// Load tokens on startup
loadTokens();

// Startup token refresh function
async function refreshTokensOnStartup() {
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    if (!accessToken || !refreshToken) {
        console.log('⏭️  Skipping startup token refresh - no tokens available');
        return;
    }
    
    try {
        if (!tokenExpiresAt || Date.now() + (10 * 60 * 1000) >= tokenExpiresAt) {
            console.log('🔄 Refreshing tokens on startup...');
            await refreshAccessToken();
        } else {
            const expiresIn = Math.floor((tokenExpiresAt - Date.now()) / 1000);
            console.log(`✅ Token still valid for ${expiresIn} seconds`);
        }
    } catch (error) {
        console.error('⚠️  Startup token refresh failed:', error.message);
    }
}

// Call startup token refresh
refreshTokensOnStartup();

// API URLs for Saudi Arabia
const ZOHO_ACCOUNTS_URL = process.env.ZOHO_ACCOUNTS_URL || 'https://accounts.zoho.sa';
const ZOHO_BOOKS_API_URL = process.env.ZOHO_BOOKS_API_URL || 'https://www.zohoapis.sa/books/v3';
const ZOHO_INVENTORY_API_URL = process.env.ZOHO_INVENTORY_API_URL || 'https://www.zohoapis.sa/inventory/v1';

// Refresh access token
async function refreshAccessToken() {
    if (!refreshToken) {
        throw new Error('No refresh token available');
    }
    
    try {
        console.log('🔄 Refreshing access token...');
        const response = await axios.post(`${ZOHO_ACCOUNTS_URL}/oauth/v2/token`, null, {
            params: {
                refresh_token: refreshToken,
                client_id: process.env.ZOHO_CLIENT_ID,
                client_secret: process.env.ZOHO_CLIENT_SECRET,
                grant_type: 'refresh_token'
            }
        });
        
        accessToken = response.data.access_token;
        tokenExpiresAt = Date.now() + (response.data.expires_in * 1000 || 3600 * 1000);
        
        saveTokens();
        console.log('✅ Token refreshed successfully');
        return accessToken;
    } catch (error) {
        console.error('Failed to refresh token:', error.response?.data || error);
        throw error;
    }
}

// Ensure token is valid
async function ensureValidToken() {
    if (!accessToken || !tokenExpiresAt || Date.now() >= tokenExpiresAt - 300000) {
        await refreshAccessToken();
    }
    return accessToken;
}

// Get redirect URI
function getRedirectUri() {
    if (process.env.ZOHO_REDIRECT_URI) {
        return process.env.ZOHO_REDIRECT_URI;
    }
    return 'http://localhost:3001/auth/callback';
}

// ==================== ROOT ENDPOINT ====================

// Root endpoint with helpful information
app.get('/', (req, res) => {
    res.send(`
        <html>
        <head>
            <title>Retail POS Backend</title>
            <style>
                body { font-family: system-ui; max-width: 600px; margin: 50px auto; padding: 20px; }
                .status { background: #f0f9ff; padding: 15px; border-radius: 8px; margin: 20px 0; }
                .error { background: #fef2f2; color: #dc2626; }
                .success { background: #f0fdf4; color: #16a34a; }
                a { color: #0ea5e9; text-decoration: none; }
                a:hover { text-decoration: underline; }
                code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }
            </style>
        </head>
        <body>
            <h1>🛍️ Retail POS Backend Server</h1>
            <div class="status">
                <p>✅ Backend is running on port ${PORT}</p>
                <p>📍 Organization ID: ${process.env.ZOHO_ORGANIZATION_ID}</p>
                <p>🌍 Region: Saudi Arabia (zoho.sa)</p>
            </div>
            
            <h2>⚠️ This is the API backend</h2>
            <p>To use the POS system, you need to open the frontend:</p>
            
            <div class="status">
                <h3>Option 1: Open the HTML file directly</h3>
                <p>Open this file in your browser:</p>
                <code>${path.join(__dirname, '..', 'retail-pos-frontend', 'index.html')}</code>
            </div>
            
            <div class="status">
                <h3>Option 2: Serve the frontend</h3>
                <p>Run this command in terminal:</p>
                <code>cd retail-pos-frontend && python3 -m http.server 3000</code>
                <p>Then visit: <a href="http://localhost:3000">http://localhost:3000</a></p>
            </div>
            
            <h2>API Endpoints</h2>
            <ul>
                <li><a href="/auth/status">/auth/status</a> - Check authentication status</li>
                <li>/auth/login - Start OAuth flow</li>
                <li>/api/items - Fetch products (requires auth)</li>
                <li>/api/customers - Fetch customers (requires auth)</li>
                <li>/api/invoices - Create invoice (POST, requires auth)</li>
            </ul>
        </body>
        </html>
    `);
});

// ==================== AUTH ENDPOINTS ====================

// Check authentication status
app.get('/auth/status', (req, res) => {
    const now = Date.now();
    const expiresIn = tokenExpiresAt ? Math.max(0, Math.floor((tokenExpiresAt - now) / 1000)) : null;
    
    res.json({ 
        authenticated: !!accessToken,
        hasRefreshToken: !!refreshToken,
        tokenExpiresIn: expiresIn,
        organizationId: process.env.ZOHO_ORGANIZATION_ID
    });
});

// Display tokens for Railway environment variable setup
app.get('/auth/tokens', (req, res) => {
    if (!accessToken) {
        return res.json({ 
            error: 'No access token available. Please authenticate first.',
            hasTokens: false,
            debug: {
                hasAccessToken: !!accessToken,
                hasRefreshToken: !!refreshToken,
                tokenExpiresAt: tokenExpiresAt
            }
        });
    }
    
    res.json({
        success: true,
        instructions: 'Copy these values to Railway environment variables:',
        environmentVariables: {
            ZOHO_ACCESS_TOKEN: accessToken,
            ZOHO_REFRESH_TOKEN: refreshToken || '', // Allow empty refresh token
            ZOHO_TOKEN_EXPIRES_AT: tokenExpiresAt ? tokenExpiresAt.toString() : ''
        },
        debug: {
            hasAccessToken: !!accessToken,
            hasRefreshToken: !!refreshToken,
            tokenExpiresAt: tokenExpiresAt,
            expiresIn: tokenExpiresAt ? Math.max(0, Math.floor((tokenExpiresAt - Date.now()) / 1000)) : null
        },
        railwayInstructions: [
            '1. Go to Railway Dashboard → Your Project → retail-pos-backend → Variables',
            '2. Add/Update the environment variables above',
            '3. Restart the service',
            '4. Tokens will persist across service restarts',
            '5. Note: Refresh token may be empty - will get one on next auth cycle'
        ]
    });
});

// OAuth login - redirect to Zoho
app.get('/auth/login', (req, res) => {
    // Request both Zoho Books and Inventory scopes for full POS functionality
    const scope = 'ZohoBooks.fullaccess.all,ZohoInventory.fullaccess.all';
    
    const authUrl = `${ZOHO_ACCOUNTS_URL}/oauth/v2/auth?` +
        `scope=${encodeURIComponent(scope)}` +
        `&client_id=${process.env.ZOHO_CLIENT_ID}` +
        `&response_type=code` +
        `&redirect_uri=${encodeURIComponent(getRedirectUri())}` +
        `&access_type=offline`;
    
    res.json({ authUrl });
});

// Manual code exchange endpoint (for httpbin redirect flow)
app.post('/auth/exchange-code', async (req, res) => {
    const { code } = req.body;
    
    if (!code) {
        return res.status(400).json({ error: 'No authorization code provided' });
    }
    
    try {
        console.log('Exchanging authorization code for tokens...');
        const tokenResponse = await axios.post(`${ZOHO_ACCOUNTS_URL}/oauth/v2/token`, null, {
            params: {
                grant_type: 'authorization_code',
                client_id: process.env.ZOHO_CLIENT_ID,
                client_secret: process.env.ZOHO_CLIENT_SECRET,
                redirect_uri: getRedirectUri(),
                code: code
            }
        });
        
        accessToken = tokenResponse.data.access_token;
        refreshToken = tokenResponse.data.refresh_token;
        tokenExpiresAt = Date.now() + (tokenResponse.data.expires_in * 1000 || 3600 * 1000);
        
        saveTokens();
        console.log('✅ Token exchange successful!');
        
        res.json({ 
            success: true, 
            message: 'Authentication successful',
            hasRefreshToken: !!refreshToken
        });
    } catch (error) {
        console.error('Token exchange error:', error.response?.data || error);
        res.status(400).json({ 
            error: 'Failed to exchange code for token',
            details: error.response?.data || error.message
        });
    }
});

// Get frontend URL for redirects
function getFrontendUrl() {
    if (process.env.FRONTEND_URL) {
        return process.env.FRONTEND_URL;
    }
    // Use Railway frontend URL in production
    if (process.env.NODE_ENV === 'production') {
        return 'https://retail-pos-frontend-production.up.railway.app';
    }
    return 'http://localhost:3000';
}

// OAuth callback
app.get('/auth/callback', async (req, res) => {
    const { code } = req.query;
    
    if (!code) {
        return res.redirect(`${getFrontendUrl()}/?auth=error`);
    }
    
    try {
        const tokenResponse = await axios.post(`${ZOHO_ACCOUNTS_URL}/oauth/v2/token`, null, {
            params: {
                grant_type: 'authorization_code',
                client_id: process.env.ZOHO_CLIENT_ID,
                client_secret: process.env.ZOHO_CLIENT_SECRET,
                redirect_uri: getRedirectUri(),
                code: code
            }
        });
        
        accessToken = tokenResponse.data.access_token;
        refreshToken = tokenResponse.data.refresh_token;
        tokenExpiresAt = Date.now() + (tokenResponse.data.expires_in * 1000 || 3600 * 1000);
        
        saveTokens();
        
        // Redirect to React app
        res.redirect(`${getFrontendUrl()}/?auth=success`);
    } catch (error) {
        console.error('Token exchange error:', error.response?.data || error);
        res.redirect(`${getFrontendUrl()}/?auth=error`);
    }
});

// Logout
app.post('/auth/logout', (req, res) => {
    accessToken = null;
    refreshToken = null;
    tokenExpiresAt = null;
    clearTokens();
    res.json({ success: true });
});

// ==================== ZOHO BOOKS API ENDPOINTS ====================

// Helper function to parse unit and get pieces per carton
function getPiecesPerCarton(unit) {
    console.log(`[UOM] Parsing unit: ${unit}`);
    
    if (!unit) {
        console.log('[UOM] No unit provided, returning 1');
        return 1;
    }
    
    // Handle patterns like C6P, C12P
    const match = unit.match(/C(\d+)P/i);
    if (match) {
        const pieces = parseInt(match[1]);
        console.log(`[UOM] Found pattern ${unit} = ${pieces} pieces per carton`);
        return pieces;
    }
    
    // CTN without number = no conversion
    if (unit.toUpperCase() === 'CTN') {
        console.log('[UOM] Plain CTN found - no piece conversion available');
        return 0;
    }
    
    console.log(`[UOM] Unknown unit pattern: ${unit}, defaulting to 1`);
    return 1;
}

// Get items from Zoho Books
app.get('/api/items', async (req, res) => {
    console.log('\n========== FETCHING ITEMS ==========');
    try {
        await ensureValidToken();
        
        const response = await axios.get(`${ZOHO_BOOKS_API_URL}/items`, {
            headers: {
                'Authorization': `Zoho-oauthtoken ${accessToken}`
            },
            params: {
                organization_id: process.env.ZOHO_ORGANIZATION_ID
            }
        });
        
        console.log(`[API] Received ${response.data.items.length} items from Zoho`);
        
        // Log first item to see all available fields
        if (response.data.items.length > 0) {
            console.log('[API] Sample item from Zoho (first item):');
            console.log(JSON.stringify(response.data.items[0], null, 2));
        }
        
        // Filter out inactive items and transform with unit conversion
        const activeItems = response.data.items.filter(item => {
            // Check multiple conditions for active status
            const isActive = item.status === 'active' && item.is_active !== false;
            if (!isActive) {
                console.log(`[FILTER] Excluding inactive item: ${item.name} (ID: ${item.item_id}, Status: ${item.status})`);
            }
            return isActive;
        });
        console.log(`[API] Filtered to ${activeItems.length} active items (excluded ${response.data.items.length - activeItems.length} inactive items)`);
        
        // Transform items with unit conversion and price calculation
        const items = activeItems.map((item, index) => {
            console.log(`\n[Item ${index + 1}] Processing: ${item.name}`);
            console.log(`  - Item ID: ${item.item_id}`);
            console.log(`  - Stored Unit: ${item.unit}`);
            console.log(`  - Zoho Price: ${item.rate} SAR`);
            
            const piecesPerCarton = getPiecesPerCarton(item.unit);
            const hasConversion = piecesPerCarton > 1;
            
            // Calculate piece price (Zoho stores carton price)
            const cartonPrice = item.rate;
            const piecePrice = hasConversion ? cartonPrice / piecesPerCarton : cartonPrice;
            
            console.log(`  - Pieces per carton: ${piecesPerCarton}`);
            console.log(`  - Has conversion: ${hasConversion}`);
            console.log(`  - Carton price: ${cartonPrice} SAR`);
            console.log(`  - Piece price: ${piecePrice.toFixed(2)} SAR`);
            console.log(`  - Default unit: ${hasConversion ? 'PCS' : 'CTN'}`);
            
            return {
                id: item.item_id,
                name: item.name,
                sku: item.sku,
                
                // Unit info
                storedUnit: item.unit,
                piecesPerCarton: piecesPerCarton,
                hasConversion: hasConversion,
                
                // Prices - DEFAULT TO PIECE PRICE
                price: piecePrice,  // Default display price (per piece)
                piecePrice: piecePrice,
                cartonPrice: cartonPrice,
                
                // For display
                defaultUnit: hasConversion ? 'PCS' : 'CTN',
                
                tax_percentage: item.tax_percentage || 15,
                description: item.description,
                stock_on_hand: item.stock_on_hand || 0,
                category: item.group_name || 'General'
            };
        });
        
        console.log(`\n[API] Successfully processed ${items.length} items`);
        console.log('========== ITEMS FETCH COMPLETE ==========\n');
        
        res.json({ items });
    } catch (error) {
        console.error('[API ERROR] Failed to fetch items:', error.response?.data || error);
        res.status(500).json({ error: 'Failed to fetch items' });
    }
});

// Get customers from Zoho Books
app.get('/api/customers', async (req, res) => {
    try {
        await ensureValidToken();
        
        const response = await axios.get(`${ZOHO_BOOKS_API_URL}/contacts`, {
            headers: {
                'Authorization': `Zoho-oauthtoken ${accessToken}`
            },
            params: {
                organization_id: process.env.ZOHO_ORGANIZATION_ID,
                contact_type: 'customer'
            }
        });
        
        res.json({ customers: response.data.contacts });
    } catch (error) {
        console.error('Error fetching customers:', error.response?.data || error);
        res.status(500).json({ error: 'Failed to fetch customers' });
    }
});

// Create invoice (main POS sale endpoint)
app.post('/api/invoices', async (req, res) => {
    console.log('\n========== CREATING INVOICE ==========');
    try {
        await ensureValidToken();
        
        const { customer_id, line_items, payment_mode, notes } = req.body;
        
        console.log('[Invoice] Request details:');
        console.log(`  - Customer ID: ${customer_id || 'Walk-in'}`);
        console.log(`  - Payment mode: ${payment_mode}`);
        console.log(`  - Line items count: ${line_items.length}`);
        
        // Log each line item transformation
        const transformedLineItems = line_items.map((item, index) => {
            console.log(`\n[Line Item ${index + 1}]`);
            console.log(`  - Item ID: ${item.item_id}`);
            console.log(`  - Quantity: ${item.quantity}`);
            console.log(`  - Unit: ${item.unit || 'NOT PROVIDED'}`);
            console.log(`  - Rate: ${item.rate} SAR`);
            console.log(`  - Tax: ${item.tax_percentage || 15}%`);
            console.log(`  - Line total: ${(item.quantity * item.rate).toFixed(2)} SAR`);
            
            // Include unit field if provided
            const lineItem = {
                item_id: item.item_id,
                quantity: item.quantity,
                rate: item.rate,
                tax_percentage: item.tax_percentage || 15
            };
            
            // Add unit field if provided
            if (item.unit) {
                lineItem.unit = item.unit;
                console.log(`  - Unit added to line item: ${item.unit}`);
            }
            
            // Add unit_conversion_id if provided
            if (item.unit_conversion_id) {
                lineItem.unit_conversion_id = item.unit_conversion_id;
                console.log(`  - Unit conversion ID added: ${item.unit_conversion_id}`);
            }
            
            return lineItem;
        });
        
        // Prepare invoice data for Zoho Books
        const invoiceData = {
            customer_id: customer_id || undefined, // Walk-in customer if not specified
            date: new Date().toISOString().split('T')[0],
            line_items: transformedLineItems,
            notes: notes || 'Sale from POS',
            terms: 'Payment on delivery',
            // Add payment if it's a cash sale
            payment_options: {
                payment_gateways: []
            }
        };
        
        console.log('\n[Invoice] Sending to Zoho Books:');
        console.log(JSON.stringify(invoiceData, null, 2));
        
        // Create invoice
        const invoiceResponse = await axios.post(
            `${ZOHO_BOOKS_API_URL}/invoices`,
            invoiceData,
            {
                headers: {
                    'Authorization': `Zoho-oauthtoken ${accessToken}`,
                    'Content-Type': 'application/json'
                },
                params: {
                    organization_id: process.env.ZOHO_ORGANIZATION_ID
                }
            }
        );
        
        const invoice = invoiceResponse.data.invoice;
        console.log('\n[Invoice] Created successfully!');
        console.log(`  - Invoice Number: ${invoice.invoice_number}`);
        console.log(`  - Invoice ID: ${invoice.invoice_id}`);
        console.log(`  - Total: ${invoice.total} SAR`);
        console.log(`  - Status: ${invoice.status}`);
        
        // Log line items as created in Zoho
        if (invoice.line_items) {
            console.log('\n[Invoice] Line items as saved in Zoho:');
            invoice.line_items.forEach((line, index) => {
                console.log(`  Line ${index + 1}: ${line.quantity} ${line.unit || 'qty'} @ ${line.rate} SAR = ${line.item_total} SAR`);
            });
        }
        
        // Payment recording removed - focusing only on invoice creation
        console.log('✅ Invoice created without payment recording (simplified mode)');
        
        console.log('========== INVOICE CREATED ==========\n');
        
        res.json({
            success: true,
            invoice: {
                invoice_id: invoice.invoice_id,
                invoice_number: invoice.invoice_number,
                total: invoice.total,
                balance: invoice.balance,
                status: invoice.status
            }
        });
        
    } catch (error) {
        console.error('\n[INVOICE ERROR] Failed to create invoice');
        console.error('Error details:', error.response?.data || error.message);
        
        // Check for inactive items error
        if (error.response?.data?.code === 2007) {
            const inactiveItemIds = error.response.data.error_info || [];
            console.error('Inactive item IDs detected:', inactiveItemIds);
            
            // Try to find which items in the cart are inactive
            const problematicItems = [];
            for (const itemId of inactiveItemIds) {
                const cartItem = req.body.line_items.find(li => li.item_id === itemId);
                if (cartItem) {
                    problematicItems.push({
                        item_id: itemId,
                        message: `Item ID ${itemId} is inactive in Zoho Books`
                    });
                }
            }
            
            res.status(400).json({ 
                error: 'One or more items are inactive or deleted in Zoho Books',
                inactiveItemIds: inactiveItemIds,
                problematicItems: problematicItems,
                message: 'Please refresh the page to reload active items, then try again'
            });
        } else {
            if (error.response?.data?.line_items) {
                console.error('Line items errors:', error.response.data.line_items);
            }
            res.status(500).json({ 
                error: 'Failed to create invoice',
                details: error.response?.data || error.message
            });
        }
        
        console.log('========== INVOICE FAILED ==========\n');
    }
});

// Get taxes
app.get('/api/taxes', async (req, res) => {
    try {
        await ensureValidToken();
        
        const response = await axios.get(`${ZOHO_BOOKS_API_URL}/settings/taxes`, {
            headers: {
                'Authorization': `Zoho-oauthtoken ${accessToken}`
            },
            params: {
                organization_id: process.env.ZOHO_ORGANIZATION_ID
            }
        });
        
        res.json({ taxes: response.data.taxes });
    } catch (error) {
        console.error('Error fetching taxes:', error.response?.data || error);
        res.status(500).json({ error: 'Failed to fetch taxes' });
    }
});

// ==================== UOM MANAGEMENT ====================

// Initialize UOM handler
function getUOMHandler() {
    return new UOMHandler(accessToken, process.env.ZOHO_ORGANIZATION_ID, ZOHO_INVENTORY_API_URL);
}

// Get available units
app.get('/api/units', async (req, res) => {
    try {
        await ensureValidToken();
        const uomHandler = getUOMHandler();
        const units = await uomHandler.getAvailableUnits();
        res.json({ units });
    } catch (error) {
        console.error('Error fetching units:', error);
        res.status(500).json({ error: 'Failed to fetch units' });
    }
});

// Update item unit
app.put('/api/items/:itemId/unit', async (req, res) => {
    try {
        await ensureValidToken();
        const { itemId } = req.params;
        const { unit } = req.body;
        
        if (!unit) {
            return res.status(400).json({ error: 'Unit is required' });
        }
        
        const uomHandler = getUOMHandler();
        const result = await uomHandler.updateItemUnit(itemId, unit);
        
        if (result.success) {
            res.json(result);
        } else {
            res.status(400).json({ error: result.error });
        }
    } catch (error) {
        console.error('Error updating item unit:', error);
        res.status(500).json({ error: 'Failed to update item unit' });
    }
});

// Convert quantity between units
app.post('/api/units/convert', (req, res) => {
    try {
        const { quantity, fromUnit, toUnit, itemUnit } = req.body;
        
        const uomHandler = getUOMHandler();
        const convertedQuantity = uomHandler.convertQuantity(
            quantity, 
            fromUnit, 
            toUnit, 
            itemUnit
        );
        
        res.json({ 
            originalQuantity: quantity,
            originalUnit: fromUnit,
            convertedQuantity,
            convertedUnit: toUnit,
            itemUnit
        });
    } catch (error) {
        console.error('Error converting units:', error);
        res.status(500).json({ error: 'Failed to convert units' });
    }
});

// ==================== INVENTORY SYNC (Optional) ====================

// Get inventory items (if you want real-time stock)
app.get('/api/inventory/items', async (req, res) => {
    try {
        await ensureValidToken();
        
        const response = await axios.get(`${ZOHO_INVENTORY_API_URL}/items`, {
            headers: {
                'Authorization': `Zoho-oauthtoken ${accessToken}`
            },
            params: {
                organization_id: process.env.ZOHO_ORGANIZATION_ID
            }
        });
        
        res.json({ items: response.data.items });
    } catch (error) {
        console.error('Error fetching inventory:', error.response?.data || error);
        res.status(500).json({ error: 'Failed to fetch inventory' });
    }
});

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`
    ========================================
    🚀 Retail POS Backend Server
    ========================================
    Server running on: http://localhost:${PORT}
    Organization ID: ${process.env.ZOHO_ORGANIZATION_ID}
    Region: Saudi Arabia (zoho.sa)
    
    Auth Status:
    - Has Access Token: ${!!accessToken}
    - Has Refresh Token: ${!!refreshToken}
    
    Available Endpoints:
    - GET  /auth/status      - Check auth status
    - GET  /auth/login       - Start OAuth flow
    - POST /auth/logout      - Clear tokens
    
    - GET  /api/items        - Fetch products
    - GET  /api/customers    - Fetch customers
    - POST /api/invoices     - Create invoice/sale
    - GET  /api/taxes        - Get tax rates
    ========================================
    `);
});
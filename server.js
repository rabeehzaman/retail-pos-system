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

// ==================== CACHING SYSTEM ====================
// Response cache for item history (sales/purchases) to reduce API calls
const historyCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes in milliseconds

// Cache helper functions
function getCacheKey(type, itemId, filters = {}) {
    const filterStr = Object.keys(filters)
        .sort()
        .map(key => `${key}:${filters[key]}`)
        .join('|');
    return `${type}_${itemId}_${filterStr}`;
}

function getCachedResponse(cacheKey) {
    const cached = historyCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
        console.log(`[CACHE] ✅ Cache hit for ${cacheKey} (age: ${Math.floor((Date.now() - cached.timestamp) / 1000)}s)`);
        return cached.data;
    }
    if (cached) {
        console.log(`[CACHE] ⏰ Cache expired for ${cacheKey}, removing`);
        historyCache.delete(cacheKey);
    }
    return null;
}

function setCachedResponse(cacheKey, data) {
    historyCache.set(cacheKey, {
        data: data,
        timestamp: Date.now()
    });
    console.log(`[CACHE] 💾 Cached response for ${cacheKey}`);
    
    // Clean up expired cache entries (prevent memory leaks)
    if (historyCache.size > 100) { // Limit cache size
        const now = Date.now();
        for (const [key, value] of historyCache.entries()) {
            if (now - value.timestamp >= CACHE_TTL) {
                historyCache.delete(key);
            }
        }
    }
}

// Clear cache when new transactions are created (optional)
function clearItemCache(itemId) {
    let deletedCount = 0;
    for (const key of historyCache.keys()) {
        if (key.includes(`_${itemId}_`)) {
            historyCache.delete(key);
            deletedCount++;
        }
    }
    if (deletedCount > 0) {
        console.log(`[CACHE] 🗑️ Cleared ${deletedCount} cache entries for item ${itemId}`);
    }
}

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
        if (!refreshToken) {
            // No refresh token available - throw specific error for re-authentication
            const hoursUntilExpiry = tokenExpiresAt ? Math.max(0, (tokenExpiresAt - Date.now()) / (1000 * 60 * 60)) : 0;
            throw new Error(`Authentication required: Access token ${tokenExpiresAt ? `expires in ${hoursUntilExpiry.toFixed(1)} hours` : 'has expired'} and no refresh token available. Please re-authenticate.`);
        }
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
                <li>/api/vendors - Fetch vendors (requires auth)</li>
                <li>/api/branches - Fetch branches (requires auth)</li>
                <li>/api/invoices - Create invoice (POST, requires auth)</li>
                <li>/api/products/:id/sales - Get product sales history</li>
                <li>/api/products/:id/purchases - Get product purchase history</li>
                <li>/api/vendors/:id/bills - Get vendor bills</li>
                <li>/api/bills/:id/details - Get bill details</li>
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
    const expiresInHours = expiresIn ? (expiresIn / 3600).toFixed(1) : null;
    const needsReauth = !accessToken || !tokenExpiresAt || now >= tokenExpiresAt - (24 * 60 * 60 * 1000); // 24 hours warning
    const critical = !accessToken || !tokenExpiresAt || now >= tokenExpiresAt - (2 * 60 * 60 * 1000); // 2 hours critical
    
    res.json({ 
        authenticated: !!accessToken,
        hasRefreshToken: !!refreshToken,
        tokenExpiresIn: expiresIn,
        tokenExpiresInHours: expiresInHours,
        organizationId: process.env.ZOHO_ORGANIZATION_ID,
        needsReauth: needsReauth,
        critical: critical,
        status: !accessToken ? 'not_authenticated' : 
                critical ? 'critical' : 
                needsReauth ? 'warning' : 'good',
        message: !accessToken ? 'Not authenticated' :
                critical ? `Token expires in ${expiresInHours}h - Re-authenticate immediately` :
                needsReauth ? `Token expires in ${expiresInHours}h - Re-authenticate soon` :
                `Token valid for ${expiresInHours}h`
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
    
    const refreshTokenIssue = !refreshToken;
    const tokenExpiringSoon = tokenExpiresAt && (Date.now() + (24 * 60 * 60 * 1000)) >= tokenExpiresAt;
    
    res.json({
        success: true,
        instructions: 'Copy these values to Railway environment variables:',
        environmentVariables: {
            ZOHO_ACCESS_TOKEN: accessToken,
            ZOHO_REFRESH_TOKEN: refreshToken || '',
            ZOHO_TOKEN_EXPIRES_AT: tokenExpiresAt ? tokenExpiresAt.toString() : ''
        },
        debug: {
            hasAccessToken: !!accessToken,
            hasRefreshToken: !!refreshToken,
            tokenExpiresAt: tokenExpiresAt,
            expiresIn: tokenExpiresAt ? Math.max(0, Math.floor((tokenExpiresAt - Date.now()) / 1000)) : null,
            expiresInHours: tokenExpiresAt ? Math.max(0, Math.floor((tokenExpiresAt - Date.now()) / (1000 * 60 * 60))) : null,
            tokenExpiringSoon: tokenExpiringSoon,
            refreshTokenMissing: refreshTokenIssue
        },
        warnings: [
            ...(refreshTokenIssue ? ['⚠️ No refresh token - authentication will fail when access token expires'] : []),
            ...(tokenExpiringSoon ? ['⚠️ Access token expires within 24 hours'] : [])
        ],
        railwayInstructions: [
            '1. Go to Railway Dashboard → Your Project → retail-pos-backend → Variables',
            '2. Add/Update the environment variables above',
            '3. Restart the service',
            '4. Tokens will persist across service restarts',
            ...(refreshTokenIssue ? ['5. ⚠️ IMPORTANT: Missing refresh token will cause auth failures!'] : ['5. ✅ Refresh token available for automatic renewal'])
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
        `&access_type=offline` +
        `&prompt=consent`;
    
    res.json({ authUrl });
});

// Manual code exchange endpoint (for httpbin redirect flow)
app.post('/auth/exchange-code', async (req, res) => {
    const { code } = req.body;
    
    if (!code) {
        return res.status(400).json({ error: 'No authorization code provided' });
    }
    
    try {
        console.log('🔄 Manual token exchange...');
        console.log('Request parameters:', {
            grant_type: 'authorization_code',
            client_id: process.env.ZOHO_CLIENT_ID,
            redirect_uri: getRedirectUri(),
            code: code ? `${code.substring(0, 20)}...` : 'null'
        });
        
        const tokenResponse = await axios.post(`${ZOHO_ACCOUNTS_URL}/oauth/v2/token`, null, {
            params: {
                grant_type: 'authorization_code',
                client_id: process.env.ZOHO_CLIENT_ID,
                client_secret: process.env.ZOHO_CLIENT_SECRET,
                redirect_uri: getRedirectUri(),
                code: code
            }
        });
        
        console.log('✅ Manual token exchange successful!');
        console.log('Response data keys:', Object.keys(tokenResponse.data));
        console.log('Has access_token:', !!tokenResponse.data.access_token);
        console.log('Has refresh_token:', !!tokenResponse.data.refresh_token);
        console.log('Full response:', JSON.stringify(tokenResponse.data, null, 2));
        
        accessToken = tokenResponse.data.access_token;
        refreshToken = tokenResponse.data.refresh_token || null;
        tokenExpiresAt = Date.now() + (tokenResponse.data.expires_in * 1000 || 3600 * 1000);
        
        // Log what we're storing
        console.log('Storing tokens:', {
            hasAccessToken: !!accessToken,
            hasRefreshToken: !!refreshToken,
            refreshTokenValue: refreshToken ? `${refreshToken.substring(0, 20)}...` : 'null'
        });
        
        saveTokens();
        
        res.json({ 
            success: true, 
            message: 'Authentication successful',
            hasRefreshToken: !!refreshToken,
            debug: {
                receivedRefreshToken: !!tokenResponse.data.refresh_token,
                storedRefreshToken: !!refreshToken
            }
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
        console.log('🔄 Exchanging authorization code for tokens...');
        console.log('Request parameters:', {
            grant_type: 'authorization_code',
            client_id: process.env.ZOHO_CLIENT_ID,
            redirect_uri: getRedirectUri(),
            code: code ? `${code.substring(0, 20)}...` : 'null'
        });
        
        const tokenResponse = await axios.post(`${ZOHO_ACCOUNTS_URL}/oauth/v2/token`, null, {
            params: {
                grant_type: 'authorization_code',
                client_id: process.env.ZOHO_CLIENT_ID,
                client_secret: process.env.ZOHO_CLIENT_SECRET,
                redirect_uri: getRedirectUri(),
                code: code
            }
        });
        
        console.log('✅ Token exchange successful!');
        console.log('Response data keys:', Object.keys(tokenResponse.data));
        console.log('Has access_token:', !!tokenResponse.data.access_token);
        console.log('Has refresh_token:', !!tokenResponse.data.refresh_token);
        console.log('Expires in:', tokenResponse.data.expires_in);
        console.log('Full response:', JSON.stringify(tokenResponse.data, null, 2));
        
        accessToken = tokenResponse.data.access_token;
        refreshToken = tokenResponse.data.refresh_token || null;
        tokenExpiresAt = Date.now() + (tokenResponse.data.expires_in * 1000 || 3600 * 1000);
        
        // Log what we're storing
        console.log('Storing tokens:', {
            hasAccessToken: !!accessToken,
            hasRefreshToken: !!refreshToken,
            refreshTokenValue: refreshToken ? `${refreshToken.substring(0, 20)}...` : 'null',
            expiresAt: new Date(tokenExpiresAt).toISOString()
        });
        
        saveTokens();
        
        // Redirect to React app
        res.redirect(`${getFrontendUrl()}/?auth=success`);
    } catch (error) {
        console.error('❌ Token exchange failed:', error.response?.data || error);
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

// Complete unit conversion mapping from Zoho Books
const UNIT_CONVERSION_MAP = {
    "PIECES": "9465000000009224",
    "C3P": "9465000000016009",
    "C4P": "9465000000009276",
    "C5P": "9465000000009284",
    "C6P": "9465000000009236",
    "C8P": "9465000000009228",
    "C10P": "9465000000009232",
    "C12P": "9465000000009224",
    "C15P": "9465000000016001",
    "C16P": "9465000000009264",
    "C18P": "9465000000009260",
    "C20P": "9465000000009240",
    "C24P": "9465000000009248",
    "C25P": "9465000000009256",
    "C26P": "9465000000009288",
    "C30P": "9465000000009252",
    "C32P": "9465000000009296",
    "C35P": "9465000000016027",
    "C36P": "9465000000009280",
    "C40P": "9465000000009300",
    "C45P": "9465000000016031",
    "C48P": "9465000000009292",
    "C50P": "9465000000009268",
    "C60P": "9465000000009244",
    "C72P": "9465000000009272",
    "C80P": "9465000000016035",
    "C100P": "9465000000016005",
    "C140P": "9465000000016013",
    "C150P": "9465000000016017",
    "BAG(4)": "9465000006156003",
    "BAG(8)": "9465000000686132",
    "RAFTHA": "9465000000366030",
    "OUTER": "9465000000366098",
    // CTN has no conversion ID (returns empty array)
    // C3(RPT) has multiple conversions - handle separately if needed
};

// Helper function to get unit conversion ID
function getUnitConversionId(unit) {
    if (!unit) return null;
    const conversionId = UNIT_CONVERSION_MAP[unit.toUpperCase()];
    console.log(`[UOM] Unit ${unit} -> Conversion ID: ${conversionId || 'NOT_FOUND'}`);
    return conversionId || null;
}

// Helper function to parse unit and get pieces per carton
function getPiecesPerCarton(unit) {
    console.log(`[UOM] Parsing unit: ${unit}`);
    
    if (!unit) {
        console.log('[UOM] No unit provided, returning 1');
        return 1;
    }
    
    // Handle patterns like C6P, C12P, C-12P, C-24P
    const match = unit.match(/C-?(\d+)P/i);
    if (match) {
        const pieces = parseInt(match[1]);
        console.log(`[UOM] Found pattern ${unit} = ${pieces} pieces per carton`);
        return pieces;
    }
    
    // Special handling for specific units
    const upperUnit = unit.toUpperCase();
    
    if (upperUnit === 'CTN') {
        console.log('[UOM] Plain CTN found - no piece conversion available');
        return 0;
    }
    
    if (upperUnit === 'BAG(8)') {
        console.log('[UOM] BAG(8) = 8 pieces per bag');
        return 8;
    }
    
    if (upperUnit === 'BAG(4)') {
        console.log('[UOM] BAG(4) = 4 pieces per bag');
        return 4;
    }
    
    // Units that are sold as-is (no conversion)
    if (['PIECES', 'RAFTHA', 'OUTER'].includes(upperUnit)) {
        console.log(`[UOM] Non-convertible unit ${unit} found - sold as-is`);
        return 1;
    }
    
    console.log(`[UOM] Unknown unit pattern: ${unit}, defaulting to 1`);
    return 1;
}

// Get items from Zoho Books
app.get('/api/items', async (req, res) => {
    console.log('\n========== FETCHING ITEMS ==========');
    try {
        await ensureValidToken();
        
        // Fetch all pages of items
        let allItems = [];
        let page = 1;
        let hasMorePages = true;
        
        while (hasMorePages) {
            console.log(`[API] Fetching page ${page}...`);
            
            const response = await axios.get(`${ZOHO_BOOKS_API_URL}/items`, {
                headers: {
                    'Authorization': `Zoho-oauthtoken ${accessToken}`
                },
                params: {
                    organization_id: process.env.ZOHO_ORGANIZATION_ID,
                    per_page: 200, // Max per page for Zoho Books
                    page: page
                }
            });
            
            if (response.data.items && response.data.items.length > 0) {
                allItems = allItems.concat(response.data.items);
                console.log(`[API] Page ${page}: ${response.data.items.length} items, Total: ${allItems.length}`);
                
                // Check if there are more pages
                if (response.data.items.length < 200) {
                    hasMorePages = false;
                } else {
                    page++;
                }
            } else {
                hasMorePages = false;
            }
        }
        
        console.log(`[API] Received ${allItems.length} items from Zoho (${page} pages)`);
        
        // Log first item to see all available fields
        if (allItems.length > 0) {
            console.log('[API] Sample item from Zoho (first item):');
            console.log(JSON.stringify(allItems[0], null, 2));
        }
        
        // Filter out inactive items and transform with unit conversion
        const activeItems = allItems.filter(item => {
            // Check multiple conditions for active status
            const isActive = item.status === 'active' && item.is_active !== false;
            if (!isActive) {
                console.log(`[FILTER] Excluding inactive item: ${item.name} (ID: ${item.item_id}, Status: ${item.status})`);
            }
            return isActive;
        });
        console.log(`[API] Filtered to ${activeItems.length} active items (excluded ${allItems.length - activeItems.length} inactive items)`);
        
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
        
        // Detailed error response for debugging
        const errorDetails = {
            error: 'Failed to fetch items',
            details: {
                message: error.message,
                status: error.response?.status,
                statusText: error.response?.statusText,
                data: error.response?.data,
                url: `${ZOHO_BOOKS_API_URL}/items`,
                organizationId: process.env.ZOHO_ORGANIZATION_ID,
                hasToken: !!accessToken,
                tokenExpiresIn: tokenExpiresAt ? Math.max(0, Math.floor((tokenExpiresAt - Date.now()) / 1000)) : null
            }
        };
        
        res.status(500).json(errorDetails);
    }
});

// Bulk fetch last sold prices for items by branch
app.post('/api/items/bulk-last-sold-prices', async (req, res) => {
    console.log('\n========== BULK FETCHING LAST SOLD PRICES ==========');
    
    try {
        await ensureValidToken();
        
        const { item_ids, branch_id } = req.body;
        
        if (!item_ids || !Array.isArray(item_ids) || item_ids.length === 0) {
            return res.status(400).json({ 
                error: 'item_ids array is required and must not be empty',
                success: false 
            });
        }
        
        if (!branch_id) {
            return res.status(400).json({ 
                error: 'branch_id is required',
                success: false 
            });
        }
        
        console.log(`[BULK PRICES] Fetching prices for ${item_ids.length} items in branch ${branch_id}`);
        
        const lastSoldPrices = new Map();
        
        // Process items in batches to avoid API rate limits
        const BATCH_SIZE = 10;
        const batches = [];
        for (let i = 0; i < item_ids.length; i += BATCH_SIZE) {
            batches.push(item_ids.slice(i, i + BATCH_SIZE));
        }
        
        let processedItems = 0;
        
        for (const batch of batches) {
            console.log(`[BATCH] Processing ${batch.length} items (${processedItems + 1}-${processedItems + batch.length})`);
            
            // Process items in parallel within each batch
            const batchPromises = batch.map(async (item_id) => {
                try {
                    // Get last 10 sales invoices to find the most recent sale for this item in this branch
                    const invoiceResponse = await axios.get(`${ZOHO_BOOKS_API_URL}/invoices`, {
                        headers: {
                            'Authorization': `Zoho-oauthtoken ${accessToken}`
                        },
                        params: {
                            organization_id: process.env.ZOHO_ORGANIZATION_ID,
                            status: 'sent',
                            sort_column: 'date',
                            sort_order: 'D',
                            per_page: 50,
                            branch_id: branch_id
                        }
                    });
                    
                    if (!invoiceResponse.data.invoices) {
                        return null;
                    }
                    
                    // Look through invoices to find the last sale of this item
                    for (const invoice of invoiceResponse.data.invoices) {
                        try {
                            // Get invoice details to check line items
                            const invoiceDetailResponse = await axios.get(`${ZOHO_BOOKS_API_URL}/invoices/${invoice.invoice_id}`, {
                                headers: {
                                    'Authorization': `Zoho-oauthtoken ${accessToken}`
                                },
                                params: {
                                    organization_id: process.env.ZOHO_ORGANIZATION_ID
                                }
                            });
                            
                            const invoiceData = invoiceDetailResponse.data.invoice;
                            
                            // Check if this invoice contains our item
                            const lineItem = invoiceData.line_items?.find(line => line.item_id === item_id);
                            
                            if (lineItem) {
                                console.log(`[FOUND] Item ${item_id} last sold on ${invoiceData.date} for ${lineItem.rate} (Invoice: ${invoiceData.invoice_number})`);
                                
                                return {
                                    item_id,
                                    price: parseFloat(lineItem.rate),
                                    date: invoiceData.date,
                                    invoice_number: invoiceData.invoice_number,
                                    unit: lineItem.unit || 'PCS',
                                    tax_mode: invoiceData.is_inclusive_tax ? 'inclusive' : 'exclusive',
                                    branch_id: branch_id
                                };
                            }
                        } catch (detailError) {
                            console.error(`[ERROR] Failed to get details for invoice ${invoice.invoice_id}:`, detailError.message);
                            continue; // Skip this invoice and try the next one
                        }
                    }
                    
                    return null; // No sale found for this item
                } catch (error) {
                    console.error(`[ERROR] Failed to fetch price for item ${item_id}:`, error.message);
                    return null;
                }
            });
            
            const batchResults = await Promise.all(batchPromises);
            
            // Store results
            batchResults.forEach((result) => {
                if (result) {
                    const key = `${result.item_id}_${result.unit}`;
                    lastSoldPrices.set(key, result);
                }
            });
            
            processedItems += batch.length;
            
            // Small delay between batches to respect API rate limits
            if (batches.indexOf(batch) < batches.length - 1) {
                await new Promise(resolve => setTimeout(resolve, 100));
            }
        }
        
        // Convert Map to object for response
        const pricesObject = {};
        lastSoldPrices.forEach((price, key) => {
            pricesObject[key] = price;
        });
        
        console.log(`[BULK PRICES] Found prices for ${lastSoldPrices.size} item-unit combinations out of ${item_ids.length} requested items`);
        
        res.json({
            success: true,
            branch_id,
            prices: pricesObject,
            processed_items: processedItems,
            found_prices: lastSoldPrices.size
        });
        
    } catch (error) {
        console.error('❌ Bulk last sold prices fetch failed:', error);
        
        const errorDetails = {
            error: 'Failed to fetch bulk last sold prices',
            success: false,
            details: error.response ? {
                status: error.response.status,
                data: error.response.data,
                url: error.config?.url
            } : {
                message: error.message
            }
        };
        
        res.status(500).json(errorDetails);
    }
});

// Get customers from Zoho Books
app.get('/api/customers', async (req, res) => {
    console.log('\n========== FETCHING CUSTOMERS ==========');
    try {
        await ensureValidToken();
        
        const { search } = req.query;
        
        // Fetch all pages of customers
        let allCustomers = [];
        let page = 1;
        let hasMorePages = true;
        
        while (hasMorePages) {
            console.log(`[API] Fetching customers page ${page}...`);
            
            const params = {
                organization_id: process.env.ZOHO_ORGANIZATION_ID,
                contact_type: 'customer',
                per_page: 200, // Max per page for Zoho Books
                page: page
            };
            
            // Add search parameter if provided
            if (search && search.trim()) {
                params.search_text = search.trim();
                console.log(`[API] Searching for: "${search.trim()}"`);
            }
            
            const response = await axios.get(`${ZOHO_BOOKS_API_URL}/contacts`, {
                headers: {
                    'Authorization': `Zoho-oauthtoken ${accessToken}`
                },
                params: params
            });
            
            if (response.data.contacts && response.data.contacts.length > 0) {
                allCustomers = allCustomers.concat(response.data.contacts);
                console.log(`[API] Page ${page}: ${response.data.contacts.length} customers, Total: ${allCustomers.length}`);
                
                // Check if there are more pages
                if (response.data.contacts.length < 200) {
                    hasMorePages = false;
                } else {
                    page++;
                }
            } else {
                hasMorePages = false;
            }
        }
        
        console.log(`[API] Received ${allCustomers.length} customers from Zoho (${page} pages)`);
        console.log('========== CUSTOMERS FETCH COMPLETE ==========\n');
        
        res.json({ customers: allCustomers });
    } catch (error) {
        console.error('Error fetching customers:', error.response?.data || error);
        
        // Detailed error response for debugging
        const errorDetails = {
            error: 'Failed to fetch customers',
            details: {
                message: error.message,
                status: error.response?.status,
                statusText: error.response?.statusText,
                data: error.response?.data,
                url: `${ZOHO_BOOKS_API_URL}/contacts`,
                organizationId: process.env.ZOHO_ORGANIZATION_ID,
                hasToken: !!accessToken,
                tokenExpiresIn: tokenExpiresAt ? Math.max(0, Math.floor((tokenExpiresAt - Date.now()) / 1000)) : null
            }
        };
        
        res.status(500).json(errorDetails);
    }
});

// Get vendors from Zoho Books
app.get('/api/vendors', async (req, res) => {
    console.log('\n========== FETCHING VENDORS ==========');
    try {
        await ensureValidToken();
        
        const { search } = req.query;
        
        // Fetch all pages of vendors
        let allVendors = [];
        let page = 1;
        let hasMorePages = true;
        
        while (hasMorePages) {
            console.log(`[API] Fetching vendors page ${page}...`);
            
            const params = {
                organization_id: process.env.ZOHO_ORGANIZATION_ID,
                contact_type: 'vendor',
                per_page: 200, // Max per page for Zoho Books
                page: page
            };
            
            // Add search parameter if provided
            if (search && search.trim()) {
                params.search_text = search.trim();
                console.log(`[API] Searching for: "${search.trim()}"`);
            }
            
            const response = await axios.get(`${ZOHO_BOOKS_API_URL}/contacts`, {
                headers: {
                    'Authorization': `Zoho-oauthtoken ${accessToken}`
                },
                params: params
            });
            
            if (response.data.contacts && response.data.contacts.length > 0) {
                allVendors = allVendors.concat(response.data.contacts);
                console.log(`[API] Page ${page}: ${response.data.contacts.length} vendors, Total: ${allVendors.length}`);
                
                // Check if there are more pages
                if (response.data.contacts.length < 200) {
                    hasMorePages = false;
                } else {
                    page++;
                }
            } else {
                hasMorePages = false;
            }
        }
        
        console.log(`[API] Received ${allVendors.length} vendors from Zoho (${page} pages)`);
        console.log('========== VENDORS FETCH COMPLETE ==========\n');
        
        res.json({ vendors: allVendors });
    } catch (error) {
        console.error('Error fetching vendors:', error.response?.data || error);
        
        // Detailed error response for debugging
        const errorDetails = {
            error: 'Failed to fetch vendors',
            details: {
                message: error.message,
                status: error.response?.status,
                statusText: error.response?.statusText,
                data: error.response?.data,
                url: `${ZOHO_BOOKS_API_URL}/contacts`,
                organizationId: process.env.ZOHO_ORGANIZATION_ID,
                hasToken: !!accessToken,
                tokenExpiresIn: tokenExpiresAt ? Math.max(0, Math.floor((tokenExpiresAt - Date.now()) / 1000)) : null
            }
        };
        
        res.status(500).json(errorDetails);
    }
});

// Get branches from Zoho Books
app.get('/api/branches', async (req, res) => {
    console.log('\n========== FETCHING BRANCHES ==========');
    try {
        await ensureValidToken();
        
        const response = await axios.get(`${ZOHO_BOOKS_API_URL}/branches`, {
            headers: {
                'Authorization': `Zoho-oauthtoken ${accessToken}`
            },
            params: {
                organization_id: process.env.ZOHO_ORGANIZATION_ID
            }
        });
        
        const branches = response.data.branches || [];
        console.log(`[Branches] Retrieved ${branches.length} branches from Zoho Books`);
        
        res.json({ 
            branches: branches,
            success: true 
        });
        
    } catch (error) {
        console.error('[Branches Error] Failed to fetch branches:', error.response?.data || error.message);
        
        // If branches are not enabled, return empty array with note
        if (error.response?.status === 400 || error.response?.status === 404) {
            console.log('[Branches] Branches feature may not be enabled for this organization');
            res.json({ 
                branches: [], 
                success: true,
                note: 'Branches feature not available or not enabled'
            });
        } else {
            res.status(500).json({ 
                error: 'Failed to fetch branches',
                message: error.response?.data?.message || error.message,
                success: false
            });
        }
    }
});

// Create invoice (main POS sale endpoint)
app.post('/api/invoices', async (req, res) => {
    console.log('\n========== CREATING INVOICE ==========');
    try {
        await ensureValidToken();
        
        const { customer_id, line_items, payment_mode, notes, branch_id, mark_as_sent, template_id, template_name, template_type } = req.body;
        
        console.log('[Invoice] Request details:');
        console.log(`  - Customer ID: ${customer_id || 'Walk-in'}`);
        console.log(`  - Payment mode: ${payment_mode}`);
        console.log(`  - Branch ID: ${branch_id || 'Not specified'}`);
        console.log(`  - Line items count: ${line_items.length}`);
        console.log(`  - Mark as sent: ${mark_as_sent ? 'Yes' : 'No (draft)'}`);
        console.log(`  - Template ID: ${template_id || 'Default template'}`);
        console.log(`  - Template Name: ${template_name || 'Default'}`);
        
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
                tax_id: item.tax_id || "9465000000007061", // Default to Standard Rate 15% tax ID
                is_taxable: true // Explicitly mark items as taxable
            };
            
            // Add unit field if provided
            if (item.unit) {
                lineItem.unit = item.unit;
                console.log(`  - Unit added to line item: ${item.unit}`);
            }
            
            // Add unit_conversion_id if provided (frontend handles conversion ID mapping)
            if (item.unit_conversion_id) {
                lineItem.unit_conversion_id = item.unit_conversion_id;
                console.log(`  - Unit conversion ID added: ${item.unit_conversion_id}`);
            }
            
            return lineItem;
        });
        
        // Prepare invoice data for Zoho Books
        const invoiceData = {
            date: new Date().toISOString().split('T')[0],
            type: 'invoice', // Specify this is a tax invoice
            is_inclusive_tax: req.body.is_inclusive_tax || false, // Support tax inclusive/exclusive
            line_items: transformedLineItems,
            notes: notes || 'Sale from POS',
            terms: 'Payment on delivery',
            // Add payment if it's a cash sale
            payment_options: {
                payment_gateways: []
            }
        };

        // Only add customer_id if a customer is selected (omit for walk-in customers)
        if (customer_id) {
            invoiceData.customer_id = customer_id;
        }
        
        // Add branch_id if specified
        if (branch_id) {
            invoiceData.branch_id = branch_id;
            console.log(`[Invoice] Including branch ID: ${branch_id}`);
        }
        
        // Add template fields if specified
        if (template_id) {
            invoiceData.template_id = template_id;
            console.log(`[Invoice] Including template ID: ${template_id}`);
        }
        if (template_name) {
            invoiceData.template_name = template_name;
            console.log(`[Invoice] Including template name: ${template_name}`);
        }
        if (template_type) {
            invoiceData.template_type = template_type;
            console.log(`[Invoice] Including template type: ${template_type}`);
        }
        
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
        
        // Mark as sent if requested
        if (mark_as_sent) {
            console.log('\n[Invoice] Marking as sent...');
            try {
                const markSentResponse = await axios.post(
                    `${ZOHO_BOOKS_API_URL}/invoices/${invoice.invoice_id}/status/sent`,
                    {},
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
                
                console.log('✅ Invoice marked as sent successfully');
                invoice.status = 'sent'; // Update status in our response
            } catch (markSentError) {
                console.error('⚠️ Failed to mark invoice as sent:', markSentError.response?.data || markSentError.message);
                // Continue with invoice creation even if marking as sent fails
            }
        }
        
        // Payment recording removed - focusing only on invoice creation
        console.log(`✅ Invoice created successfully${mark_as_sent ? ' and marked as sent' : ' as draft'}`);
        
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

// Download invoice PDF
app.get('/api/invoices/:invoiceId/download', async (req, res) => {
    console.log('\n========== DOWNLOADING INVOICE PDF ==========');
    try {
        await ensureValidToken();
        
        const { invoiceId } = req.params;
        console.log(`[Download] Invoice ID: ${invoiceId}`);
        
        // Get invoice PDF from Zoho Books
        const response = await axios.get(`${ZOHO_BOOKS_API_URL}/invoices/${invoiceId}`, {
            headers: {
                'Authorization': `Zoho-oauthtoken ${accessToken}`,
                'Accept': 'application/pdf'
            },
            params: {
                organization_id: process.env.ZOHO_ORGANIZATION_ID,
                accept: 'pdf'
            },
            responseType: 'stream'
        });
        
        console.log('[Download] PDF retrieved from Zoho Books');
        
        // Set headers for PDF download
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="Invoice_${invoiceId}.pdf"`);
        
        // Pipe the PDF stream to the response
        response.data.pipe(res);
        
        console.log('[Download] PDF download started');
        console.log('========== DOWNLOAD COMPLETE ==========\n');
        
    } catch (error) {
        console.error('[Download Error] Failed to download invoice:', error.response?.data || error.message);
        
        // Try alternative approach - get invoice details first, then PDF
        try {
            console.log('[Download] Trying alternative PDF download method...');
            
            const invoiceResponse = await axios.get(`${ZOHO_BOOKS_API_URL}/invoices/${req.params.invoiceId}/pdf`, {
                headers: {
                    'Authorization': `Zoho-oauthtoken ${accessToken}`
                },
                params: {
                    organization_id: process.env.ZOHO_ORGANIZATION_ID
                },
                responseType: 'stream'
            });
            
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', `attachment; filename="Invoice_${req.params.invoiceId}.pdf"`);
            
            invoiceResponse.data.pipe(res);
            console.log('[Download] Alternative method succeeded');
            
        } catch (altError) {
            console.error('[Download Error] Alternative method also failed:', altError.response?.data || altError.message);
            
            // Provide specific error codes for frontend handling
            const status = error.response?.status || altError.response?.status || 500;
            const errorMessage = status === 404 
                ? 'Invoice PDF not found. It may still be generating.'
                : status === 401 
                ? 'Authentication error. Please refresh and try again.'
                : 'Failed to download invoice PDF. Please try again.';
                
            res.status(status).json({ 
                error: errorMessage,
                details: error.response?.data || error.message,
                invoiceId: req.params.invoiceId,
                statusCode: status
            });
        }
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

// Get product sales history (last 10 sales of a specific product)
app.get('/api/products/:productId/sales', async (req, res) => {
    const startTime = Date.now();
    let apiCallCount = 0;
    let cacheHit = false;
    
    console.log('\n========== FETCHING PRODUCT SALES HISTORY ==========');
    try {
        await ensureValidToken();
        
        const { productId } = req.params;
        const { customer_id } = req.query;
        
        console.log('[Product Sales] Request params:');
        console.log(`  - Product ID: ${productId}`);
        console.log(`  - Customer Filter: ${customer_id || 'none'}`);
        
        // Check cache first
        const cacheKey = getCacheKey('sales', productId, { customer_id });
        const cachedResponse = getCachedResponse(cacheKey);
        if (cachedResponse) {
            cacheHit = true;
            const responseTime = Date.now() - startTime;
            console.log(`[PERFORMANCE] Sales History - Cache Hit | Response: ${responseTime}ms | API Calls: 0`);
            return res.json(cachedResponse);
        }
        
        // Build query parameters - Zoho supports item_id filter!
        const params = {
            organization_id: process.env.ZOHO_ORGANIZATION_ID,
            item_id: productId, // This filters invoices by product
            per_page: 10, // Last 10 sales
            page: 1,
            sort_column: 'date',
            sort_order: 'D' // Descending (newest first)
        };
        
        // Optionally filter by customer too
        if (customer_id && customer_id !== 'undefined') {
            params.customer_id = customer_id;
            console.log(`[Product Sales] Also filtering by customer: ${customer_id}`);
        }
        
        // Fetch invoices containing this product from Zoho Books
        const response = await axios.get(`${ZOHO_BOOKS_API_URL}/invoices`, {
            headers: {
                'Authorization': `Zoho-oauthtoken ${accessToken}`
            },
            params: params
        });
        apiCallCount++; // Count the initial invoices API call
        
        const invoices = response.data.invoices || [];
        
        console.log(`[Product Sales] Found ${invoices.length} invoices containing product ${productId}`);
        
        // PARALLEL: Fetch all invoice details concurrently for better performance
        const salesData = [];
        console.log(`[Product Sales] Fetching ${invoices.length} invoice details in parallel...`);
        
        const invoiceDetailPromises = invoices.map(invoice => 
            axios.get(`${ZOHO_BOOKS_API_URL}/invoices/${invoice.invoice_id}`, {
                headers: { 'Authorization': `Zoho-oauthtoken ${accessToken}` },
                params: { organization_id: process.env.ZOHO_ORGANIZATION_ID }
            }).then(response => ({ invoice, fullInvoice: response.data.invoice }))
              .catch(error => {
                  console.error(`[Product Sales] Error fetching invoice ${invoice.invoice_id} details:`, error.message);
                  return { invoice, error: error.message };
              })
        );
        
        const invoiceDetails = await Promise.all(invoiceDetailPromises);
        apiCallCount += invoices.length; // Count the parallel invoice detail API calls
        console.log(`[Product Sales] ✅ Completed ${invoiceDetails.length} parallel requests`);
        
        // Process the results
        for (const { invoice, fullInvoice, error } of invoiceDetails) {
            if (error) {
                // Still include basic info even if we can't get quantity
                salesData.push({
                    invoice_id: invoice.invoice_id,
                    invoice_number: invoice.invoice_number,
                    date: invoice.date,
                    customer_id: invoice.customer_id,
                    customer_name: invoice.customer_name || 'Walk-in Customer',
                    quantity: 'N/A',
                    unit: 'N/A',
                    rate: 0,
                    total: 0,
                    status: invoice.status,
                    is_paid: invoice.balance === 0 || invoice.status === 'paid'
                });
            } else {
                // Find the line item for this product
                const productLineItem = fullInvoice.line_items?.find(item => item.item_id === productId);
                
                if (productLineItem) {
                    salesData.push({
                        invoice_id: invoice.invoice_id,
                        invoice_number: invoice.invoice_number,
                        date: invoice.date,
                        customer_id: invoice.customer_id,
                        customer_name: invoice.customer_name || 'Walk-in Customer',
                        quantity: productLineItem.quantity,
                        unit: productLineItem.unit || 'PCS',
                        rate: productLineItem.rate,
                        total: productLineItem.item_total,
                        status: invoice.status,
                        is_paid: invoice.balance === 0 || invoice.status === 'paid'
                    });
                }
            }
        }
        
        console.log(`[Product Sales] Compiled sales data for ${salesData.length} transactions`);
        console.log('========== PRODUCT SALES HISTORY FETCHED ==========\n');
        
        const responseData = {
            success: true,
            product_id: productId,
            sales: salesData,
            total_sales: salesData.length,
            customer_filter: customer_id || null
        };
        
        // Cache the response
        setCachedResponse(cacheKey, responseData);
        
        // Performance metrics
        const responseTime = Date.now() - startTime;
        console.log(`[PERFORMANCE] Sales History - optimized | Response: ${responseTime}ms | API Calls: ${apiCallCount} | Results: ${salesData.length}`);
        
        res.json(responseData);
        
    } catch (error) {
        console.error('[Product Sales Error]:', error.response?.data || error.message);
        res.status(500).json({ 
            error: 'Failed to fetch product sales history',
            details: error.response?.data || error.message
        });
    }
});

// Get product purchase history (last 10 purchases of a specific product)
app.get('/api/products/:productId/purchases', async (req, res) => {
    const startTime = Date.now();
    let apiCallCount = 0;
    let approachUsed = 'optimized';
    let cacheHit = false;
    
    console.log('\n========== FETCHING PRODUCT PURCHASE HISTORY ==========');
    try {
        await ensureValidToken();
        
        const { productId } = req.params;
        const { vendor_id } = req.query;
        
        console.log('[Product Purchases] Request params:');
        console.log(`  - Product ID: ${productId}`);
        console.log(`  - Vendor Filter: ${vendor_id || 'none'}`);
        
        // Check cache first
        const cacheKey = getCacheKey('purchases', productId, { vendor_id });
        const cachedResponse = getCachedResponse(cacheKey);
        if (cachedResponse) {
            cacheHit = true;
            const responseTime = Date.now() - startTime;
            console.log(`[PERFORMANCE] Purchase History - Cache Hit | Response: ${responseTime}ms | API Calls: 0`);
            return res.json(cachedResponse);
        }
        
        console.log(`[Product Purchases] Using optimized approach - filtering bills by item ${productId}...`);
        
        // OPTIMIZED: Use item_id parameter for direct filtering
        const params = {
            organization_id: process.env.ZOHO_ORGANIZATION_ID,
            item_id: productId, // 🚀 Direct filtering - only returns bills containing this item!
            per_page: 10, // Reduced since all returned bills contain the item
            sort_column: 'date',
            sort_order: 'D' // Descending (newest first)
        };
        
        // Optionally filter by vendor
        if (vendor_id && vendor_id !== 'undefined') {
            params.vendor_id = vendor_id;
            console.log(`[Product Purchases] Also filtering by vendor: ${vendor_id}`);
        }
        
        // Fetch bills from Zoho Books with item filter
        const response = await axios.get(`${ZOHO_BOOKS_API_URL}/bills`, {
            headers: {
                'Authorization': `Zoho-oauthtoken ${accessToken}`
            },
            params: params
        });
        apiCallCount++; // Count the initial bills API call
        
        const bills = response.data.bills || [];
        console.log(`[Product Purchases] Found ${bills.length} bills containing item ${productId}`);
        
        const purchaseData = [];
        let checkedCount = 0;
        const targetResults = Math.min(10, bills.length); // Limit to available bills
        
        // PARALLEL: Fetch all bill details concurrently for better performance
        console.log(`[Product Purchases] Fetching ${targetResults} bill details in parallel...`);
        
        const billDetailPromises = bills.slice(0, targetResults).map(bill => 
            axios.get(`${ZOHO_BOOKS_API_URL}/bills/${bill.bill_id}`, {
                headers: { 'Authorization': `Zoho-oauthtoken ${accessToken}` },
                params: { organization_id: process.env.ZOHO_ORGANIZATION_ID }
            }).then(response => ({ bill, fullBill: response.data.bill }))
              .catch(error => {
                  console.error(`[Product Purchases] Error fetching bill ${bill.bill_id} details:`, error.message);
                  return { bill, error: error.message };
              })
        );
        
        const billDetails = await Promise.all(billDetailPromises);
        apiCallCount += targetResults; // Count the parallel detail API calls
        console.log(`[Product Purchases] ✅ Completed ${billDetails.length} parallel requests`);
        
        // Process the results
        for (let i = 0; i < billDetails.length; i++) {
            const { bill, fullBill, error } = billDetails[i];
            
            if (error) {
                console.log(`[Product Purchases] ⚠️ Skipping bill ${bill.bill_number} due to error: ${error}`);
                continue;
            }
            
            // Debug logging for first bill
            if (i === 0 && fullBill.line_items?.length > 0) {
                console.log(`[DEBUG] Parallel approach working - bill contains ${fullBill.line_items?.length} line items`);
                const itemMatch = fullBill.line_items?.find(item => String(item.item_id) === String(productId));
                if (itemMatch) {
                    console.log(`[DEBUG] ✅ Confirmed item ${productId} found in line items`);
                }
            }
            
            // Find the line item for this product
            const productLineItem = fullBill.line_items?.find(item => String(item.item_id) === String(productId));
            
            if (productLineItem) {
                purchaseData.push({
                    bill_id: bill.bill_id,
                    bill_number: bill.bill_number,
                    date: bill.date,
                    vendor_id: bill.vendor_id,
                    vendor_name: bill.vendor_name || 'Unknown Vendor',
                    quantity: productLineItem.quantity,
                    unit: productLineItem.unit || 'PCS',
                    rate: productLineItem.rate,
                    total: productLineItem.item_total,
                    status: bill.status,
                    is_paid: bill.balance === 0 || bill.status === 'paid'
                });
                console.log(`[Product Purchases] ✅ Added bill ${bill.bill_number} (${purchaseData.length}/${targetResults})`);
            } else {
                console.log(`[Product Purchases] ⚠️ Item not found in bill ${bill.bill_number} line items`);
            }
        }
        
        // If no bills found with direct filtering, try fallback approach
        if (purchaseData.length === 0) {
            approachUsed = 'fallback';
            console.log(`[Product Purchases] No bills found with item_id filter. Trying fallback approach...`);
            
            try {
                // Fallback: Fetch recent bills and manually filter (limited search for performance)
                const fallbackResponse = await axios.get(`${ZOHO_BOOKS_API_URL}/bills`, {
                    headers: {
                        'Authorization': `Zoho-oauthtoken ${accessToken}`
                    },
                    params: {
                        organization_id: process.env.ZOHO_ORGANIZATION_ID,
                        per_page: 30, // Limited search for performance
                        sort_column: 'date',
                        sort_order: 'D',
                        ...(vendor_id && vendor_id !== 'undefined' && { vendor_id })
                    }
                });
                apiCallCount++; // Count the fallback bills API call
                
                const fallbackBills = fallbackResponse.data.bills || [];
                console.log(`[Product Purchases] Fallback: Checking ${Math.min(10, fallbackBills.length)} recent bills...`);
                
                // PARALLEL: Also use parallel processing for fallback
                const fallbackBillsToCheck = fallbackBills.slice(0, 10); // Limit to 10 for performance
                console.log(`[Product Purchases] Fallback: Fetching ${fallbackBillsToCheck.length} bill details in parallel...`);
                
                const fallbackPromises = fallbackBillsToCheck.map(bill => 
                    axios.get(`${ZOHO_BOOKS_API_URL}/bills/${bill.bill_id}`, {
                        headers: { 'Authorization': `Zoho-oauthtoken ${accessToken}` },
                        params: { organization_id: process.env.ZOHO_ORGANIZATION_ID }
                    }).then(response => ({ bill, fullBill: response.data.bill }))
                      .catch(error => {
                          console.error(`[Product Purchases] Fallback error for ${bill.bill_id}:`, error.message);
                          return { bill, error: error.message };
                      })
                );
                
                const fallbackDetails = await Promise.all(fallbackPromises);
                apiCallCount += fallbackBillsToCheck.length; // Count the fallback detail API calls
                
                for (const { bill, fullBill, error } of fallbackDetails) {
                    if (error) continue;
                    
                    const productLineItem = fullBill.line_items?.find(
                        item => String(item.item_id) === String(productId)
                    );
                    
                    if (productLineItem) {
                        purchaseData.push({
                            bill_id: bill.bill_id,
                            bill_number: bill.bill_number,
                            date: bill.date,
                            vendor_id: bill.vendor_id,
                            vendor_name: bill.vendor_name || 'Unknown Vendor',
                            quantity: productLineItem.quantity,
                            unit: productLineItem.unit || 'PCS',
                            rate: productLineItem.rate,
                            total: productLineItem.item_total,
                            status: bill.status,
                            is_paid: bill.balance === 0 || bill.status === 'paid'
                        });
                        console.log(`[Product Purchases] Fallback: Found match in ${bill.bill_number}`);
                        if (purchaseData.length >= 10) break;
                    }
                }
                console.log(`[Product Purchases] Fallback complete: Found ${purchaseData.length} bills (checked ${fallbackBillsToCheck.length})`);
            } catch (fallbackError) {
                console.error(`[Product Purchases] Fallback approach failed:`, fallbackError.message);
            }
        }
        
        console.log(`[Product Purchases] Final result: ${purchaseData.length} bills containing item ${productId}`);
        console.log('========== PRODUCT PURCHASE HISTORY FETCHED ==========\n');
        
        const responseData = {
            success: true,
            product_id: productId,
            purchases: purchaseData,
            total_purchases: purchaseData.length,
            vendor_filter: vendor_id || null
        };
        
        // Cache the response
        setCachedResponse(cacheKey, responseData);
        
        // Performance metrics
        const responseTime = Date.now() - startTime;
        console.log(`[PERFORMANCE] Purchase History - ${approachUsed} | Response: ${responseTime}ms | API Calls: ${apiCallCount} | Results: ${purchaseData.length}`);
        
        res.json(responseData);
        
    } catch (error) {
        console.error('[Product Purchases Error]:', error.response?.data || error.message);
        
        // If main approach fails due to item_id parameter not supported, the fallback will handle it
        if (error.response?.status === 400 && error.response?.data?.message?.includes('item_id')) {
            console.log(`[Product Purchases] item_id parameter not supported, fallback logic will handle this...`);
        }
        
        res.status(500).json({ 
            error: 'Failed to fetch product purchase history',
            details: error.response?.data || error.message
        });
    }
});

// Get vendor bills history 
app.get('/api/vendors/:vendorId/bills', async (req, res) => {
    console.log('\n========== FETCHING VENDOR BILLS ==========');
    try {
        await ensureValidToken();
        
        const { vendorId } = req.params;
        const { from_date, to_date, page = 1, per_page = 50, status } = req.query;
        
        console.log(`[Vendor Bills] Vendor ID: ${vendorId}`);
        console.log(`[Vendor Bills] Date range: ${from_date || 'any'} to ${to_date || 'any'}`);
        console.log(`[Vendor Bills] Page: ${page}, Per page: ${per_page}`);
        
        // Build query parameters
        const params = {
            organization_id: process.env.ZOHO_ORGANIZATION_ID,
            vendor_id: vendorId,
            per_page: Math.min(per_page, 200), // Zoho max is 200
            page: page,
            sort_column: 'date',
            sort_order: 'D' // Descending (newest first)
        };
        
        // Add optional filters
        if (from_date) params.from_date = from_date;
        if (to_date) params.to_date = to_date;
        if (status) params.status = status; // draft, open, paid, void, overdue, etc.
        
        // Fetch bills from Zoho Books
        const response = await axios.get(`${ZOHO_BOOKS_API_URL}/bills`, {
            headers: {
                'Authorization': `Zoho-oauthtoken ${accessToken}`
            },
            params: params
        });
        
        const bills = response.data.bills || [];
        
        console.log(`[Vendor Bills] Found ${bills.length} bills`);
        
        // Transform bill data for frontend
        const transformedBills = bills.map(bill => ({
            bill_id: bill.bill_id,
            bill_number: bill.bill_number,
            date: bill.date,
            due_date: bill.due_date,
            vendor_name: bill.vendor_name,
            status: bill.status,
            total: bill.total,
            balance: bill.balance,
            currency_code: bill.currency_code,
            created_time: bill.created_time,
            last_modified_time: bill.last_modified_time,
            // Include line items summary
            line_items_count: bill.line_items ? bill.line_items.length : 0,
            // Payment status
            is_paid: bill.balance === 0,
            payment_terms: bill.payment_terms,
            // Additional useful fields
            reference_number: bill.reference_number,
            notes: bill.notes
        }));
        
        // Get vendor details for context
        let vendorDetails = null;
        if (bills.length > 0) {
            vendorDetails = {
                name: bills[0].vendor_name,
                total_bills: response.data.page_context?.total || bills.length,
                total_value: bills.reduce((sum, bill) => sum + parseFloat(bill.total || 0), 0)
            };
        }
        
        console.log('========== VENDOR BILLS FETCHED ==========\n');
        
        res.json({
            success: true,
            vendor: vendorDetails,
            bills: transformedBills,
            pagination: {
                page: parseInt(page),
                per_page: parseInt(per_page),
                total: response.data.page_context?.total || bills.length,
                has_more_page: response.data.page_context?.has_more_page || false
            }
        });
        
    } catch (error) {
        console.error('[Vendor Bills Error]:', error.response?.data || error.message);
        res.status(500).json({ 
            error: 'Failed to fetch vendor bills',
            details: error.response?.data || error.message
        });
    }
});

// Get detailed bill with line items
app.get('/api/bills/:billId/details', async (req, res) => {
    console.log('\n========== FETCHING BILL DETAILS ==========');
    try {
        await ensureValidToken();
        
        const { billId } = req.params;
        console.log(`[Bill Details] Bill ID: ${billId}`);
        
        // Fetch detailed bill from Zoho Books
        const response = await axios.get(`${ZOHO_BOOKS_API_URL}/bills/${billId}`, {
            headers: {
                'Authorization': `Zoho-oauthtoken ${accessToken}`
            },
            params: {
                organization_id: process.env.ZOHO_ORGANIZATION_ID
            }
        });
        
        const bill = response.data.bill;
        
        console.log(`[Bill Details] Bill #${bill.bill_number}`);
        console.log(`[Bill Details] Line items: ${bill.line_items?.length || 0}`);
        
        // Transform for frontend with full details
        const detailedBill = {
            ...bill,
            // Enhanced line items with product details
            line_items: bill.line_items?.map(item => ({
                line_item_id: item.line_item_id,
                item_id: item.item_id,
                name: item.name,
                description: item.description,
                quantity: item.quantity,
                unit: item.unit,
                rate: item.rate,
                discount: item.discount,
                tax_percentage: item.tax_percentage,
                item_total: item.item_total,
                sku: item.sku,
                // Additional fields for history tracking
                item_order: item.item_order
            })),
            // Vendor information
            vendor_details: {
                vendor_id: bill.vendor_id,
                vendor_name: bill.vendor_name,
                email: bill.email,
                billing_address: bill.billing_address
            },
            // Payment information
            payment_details: {
                payment_terms: bill.payment_terms,
                payment_terms_label: bill.payment_terms_label,
                is_paid: bill.balance === 0,
                payment_made: bill.payment_made,
                payments: bill.payments || []
            }
        };
        
        console.log('========== BILL DETAILS FETCHED ==========\n');
        
        res.json({
            success: true,
            bill: detailedBill
        });
        
    } catch (error) {
        console.error('[Bill Details Error]:', error.response?.data || error.message);
        res.status(500).json({ 
            error: 'Failed to fetch bill details',
            details: error.response?.data || error.message
        });
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
    - GET  /api/vendors      - Fetch vendors
    - GET  /api/branches     - Fetch branches
    - POST /api/invoices     - Create invoice/sale
    - GET  /api/taxes        - Get tax rates
    - GET  /api/products/:id/sales      - Product sales history
    - GET  /api/products/:id/purchases  - Product purchase history
    - GET  /api/vendors/:id/bills       - Vendor bills
    - GET  /api/bills/:id/details       - Bill details
    ========================================
    `);
});
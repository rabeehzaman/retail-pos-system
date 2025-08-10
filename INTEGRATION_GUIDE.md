# Zoho Books POS Integration Guide

## Overview
This project integrates your Retail POS with Zoho Books using the same organization as your Transfer Order POS.

## Architecture

```
[React POS Frontend] → [Express Backend] → [Zoho Books/Inventory APIs]
        ↓                     ↓                        ↓
    UI & Cart           OAuth & Token Mgmt      Invoices & Items
    Customer Select     API Proxying            Inventory Sync
    Payment Flow        Error Handling          Tax Management
```

## Key Features

1. **Shared Organization**: Both POS systems use the same Zoho organization (ID: 150000163897)
2. **OAuth 2.0 Authentication**: Secure token-based authentication with auto-refresh
3. **Real-time Sync**: Items, customers, and inventory from Zoho Books
4. **Invoice Creation**: Automatic invoice generation on sale completion
5. **Payment Recording**: Cash and card payment options with automatic payment recording
6. **Multi-currency**: SAR with 15% VAT for Saudi Arabia

## Setup Instructions

### 1. Install Backend Dependencies

```bash
cd retail-pos-backend
npm install
```

### 2. Configure Environment

The `.env` file is already configured with:
- Same Zoho credentials as Transfer Order POS
- Same organization ID (150000163897)
- Saudi Arabia region endpoints
- Port 3001 (to avoid conflict with Transfer Order POS on 3000)

### 3. Start the Backend Server

```bash
cd retail-pos-backend
npm start
```

The server will run on http://localhost:3001

### 4. Open the Frontend

1. Open `retail-pos-frontend/index.html` in your browser
2. Or serve it with a local server:
   ```bash
   cd retail-pos-frontend
   python3 -m http.server 3000
   ```
   Then visit http://localhost:3000

### 5. Authenticate with Zoho

1. Click "Connect to Zoho" button in the POS
2. Login with your Zoho credentials
3. Authorize the application
4. You'll be redirected back to the POS

## API Endpoints

### Authentication
- `GET /auth/status` - Check authentication status
- `GET /auth/login` - Start OAuth flow
- `POST /auth/logout` - Clear tokens

### Zoho Books Integration
- `GET /api/items` - Fetch products from Zoho Books
- `GET /api/customers` - Fetch customers
- `POST /api/invoices` - Create invoice/sale
- `GET /api/taxes` - Get tax rates

### Optional Inventory
- `GET /api/inventory/items` - Real-time inventory levels

## Data Flow

### Sale Process
1. **Product Selection**: Items fetched from Zoho Books
2. **Cart Management**: Local cart with quantity controls
3. **Customer Selection**: Optional customer from Zoho Books
4. **Payment**: Choose cash or card
5. **Invoice Creation**: 
   - Creates invoice in Zoho Books
   - Records payment automatically
   - Returns invoice number

### Token Management
- Access tokens valid for 1 hour
- Auto-refresh 5 minutes before expiry
- Persistent storage in `tokens.json`
- Fallback to environment variables

## Integration Points

### Shared with Transfer Order POS
- Same OAuth app (Client ID/Secret)
- Same organization ID
- Same region (Saudi Arabia)
- Compatible token storage

### Differences
- Transfer Order POS uses Zoho Inventory API
- Retail POS uses Zoho Books API (with optional Inventory)
- Different ports (3000 vs 3001)
- Different scopes (Inventory vs Books)

## Troubleshooting

### Authentication Issues
1. Check if tokens.json exists in backend folder
2. Verify OAuth credentials in .env
3. Ensure redirect URI matches configuration

### API Errors
1. Check backend console for detailed errors
2. Verify organization ID is correct
3. Ensure proper scopes are authorized

### CORS Issues
If running frontend from file://, use a local server instead:
```bash
python3 -m http.server 3000
# or
npx serve retail-pos-frontend
```

## Production Deployment

### Backend (similar to Transfer Order POS)
1. Set environment variables on server
2. Update redirect URI to production domain
3. Enable HTTPS for security
4. Consider using PM2 or Docker

### Frontend
1. Build optimized React bundle
2. Serve from CDN or static hosting
3. Update BACKEND_URL in POSApp.jsx
4. Enable PWA features for offline capability

## Security Notes

1. **Never expose credentials in frontend code**
2. **Always proxy Zoho API calls through backend**
3. **Use HTTPS in production**
4. **Implement rate limiting**
5. **Add user authentication layer**

## Next Steps

1. **Add barcode scanning** for quick product lookup
2. **Implement offline mode** with sync queue
3. **Add receipt printing** via browser print API
4. **Create reports dashboard** using Zoho Books data
5. **Add multi-location support** for inventory
6. **Implement discounts and promotions**
7. **Add cash drawer integration**
8. **Create mobile app** using React Native

## Support

For Zoho API documentation:
- [Zoho Books API](https://www.zoho.com/books/api/v3/)
- [Zoho Inventory API](https://www.zoho.com/inventory/api/v1/)

For OAuth issues:
- [Zoho OAuth Setup](https://www.zoho.com/accounts/protocol/oauth-setup.html)
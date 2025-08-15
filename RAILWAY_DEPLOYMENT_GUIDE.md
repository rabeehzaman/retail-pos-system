

## ⚙️ Phase 2: Environment Variables Setup

### Configure Backend Environment Variables
Go to Railway Dashboard → Your Project → Backend Service → Variables

Add these variables:

```env
# Zoho OAuth Credentials
ZOHO_CLIENT_ID=1000.ZF3REMRFJZM9F7BJIMEMWV1HOLT74K
ZOHO_CLIENT_SECRET=09913adad9d4c6aa4db873a053bef2f9368d553f1a
ZOHO_ORGANIZATION_ID=60032348952

# Railway-specific OAuth Settings
ZOHO_REDIRECT_URI=https://your-backend.up.railway.app/auth/callback
RAILWAY_PUBLIC_DOMAIN=your-backend.up.railway.app

# API URLs (Global Region)
ZOHO_ACCOUNTS_URL=https://accounts.zoho.com
ZOHO_BOOKS_API_URL=https://www.zohoapis.com/books/v3
ZOHO_INVENTORY_API_URL=https://www.zohoapis.com/inventory/v1

# Server Configuration
PORT=3001
NODE_ENV=production
```

### 🔄 Replace Railway URLs
Replace `your-backend.up.railway.app` with your actual Railway backend URL.

---

## 🌐 Phase 3: Zoho API Console Updates

### Update Authorized Redirect URIs
1. Go to [Zoho API Console](https://api-console.zoho.com/)
2. Find your application with Client ID: `1000.ZF3REMRFJZM9F7BJIMEMWV1HOLT74K`
3. Update **Authorized Redirect URIs** to:
   ```
   https://your-backend.up.railway.app/auth/callback
   ```
4. **Save** the configuration

---

## 🎨 Phase 4: Frontend Deployment

### Option A: Deploy Frontend to Railway
```bash
# Add frontend service
railway add --name frontend

# Deploy frontend
railway up --service frontend
```

### Option B: Static Hosting (Netlify/Vercel)
1. Update API URL in frontend code:
   ```javascript
   const BACKEND_URL = "https://your-backend.up.railway.app";
   ```
2. Deploy to preferred static host

---

## 🧪 Phase 5: Testing & Verification

### Test Backend Endpoints
```bash
# Check health
curl https://your-backend.up.railway.app/health

# Check auth status
curl https://your-backend.up.railway.app/auth/status

# Get login URL
curl https://your-backend.up.railway.app/auth/login
```

### Test Authentication Flow
1. Visit: `https://your-frontend.up.railway.app`
2. Click "Connect to Zoho"
3. Complete OAuth flow
4. Verify data sync works

### Expected Results
- ✅ Backend responds to health check
- ✅ Frontend loads without errors
- ✅ OAuth redirect works (no localhost errors)
- ✅ Items and customers sync from Zoho
- ✅ Invoice creation works

---

## 🔒 Phase 6: Permanent Authentication Setup

### Add Startup Token Refresh
Update backend with automatic token refresh on startup (copy from TransferOrderPOS):

```javascript
// Add to server.js
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

// Call on startup
refreshTokensOnStartup();
```

---

## 📊 Phase 7: Production Optimizations

### Enable Railway Features
```bash
# Set up custom domain (optional)
railway domain

# Configure auto-scaling
railway config set RAILWAY_STATIC_URL=true
```

### Add Monitoring
Add to `package.json`:
```json
{
  "scripts": {
    "start": "node server.js",
    "health": "curl $RAILWAY_STATIC_URL/health"
  }
}
```

### Set Up Logging
```javascript
// Add to server.js
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
    next();
});
```

---

## 🚨 Troubleshooting

### Common Issues & Solutions

**❌ OAuth Redirect Error**
- **Cause:** Redirect URI mismatch
- **Solution:** Double-check Railway URL matches Zoho console exactly

**❌ Environment Variables Not Working**
- **Cause:** Variables not set in Railway dashboard
- **Solution:** Go to Railway → Variables tab, add all required vars

**❌ CORS Errors**
- **Cause:** Frontend can't reach backend
- **Solution:** Add CORS headers for your frontend domain

**❌ Token Refresh Fails**
- **Cause:** Refresh token expired or invalid
- **Solution:** Re-authenticate through OAuth flow

**❌ 502 Bad Gateway**
- **Cause:** Backend not responding on correct port
- **Solution:** Ensure `PORT` environment variable is set

### Debug Commands
```bash
# Check Railway logs
railway logs --service backend

# Check environment variables
railway variables --service backend

# Restart service
railway restart --service backend
```

---

## ✅ Post-Deployment Checklist

- [ ] Railway backend deployed successfully
- [ ] Railway frontend deployed successfully  
- [ ] Environment variables configured
- [ ] Zoho OAuth redirect URI updated
- [ ] Authentication flow tested
- [ ] Items sync from Zoho working
- [ ] Customer sync working
- [ ] Invoice creation working
- [ ] Auto token refresh implemented
- [ ] Production monitoring setup
- [ ] Custom domain configured (optional)

---

## 🎯 Success Criteria

Your TMR POS system is successfully deployed when:

1. ✅ **Backend Health Check Passes**
   - `GET /health` returns 200 with auth status

2. ✅ **Frontend Loads Properly**
   - No console errors, proper branding ("TMR POS")

3. ✅ **OAuth Flow Works**
   - Can authenticate with Zoho without localhost errors

4. ✅ **Data Sync Functions**
   - Items and customers load from Zoho
   - Proper pagination for 2000+ items

5. ✅ **POS Features Work**
   - Add items to cart
   - Edit prices and quantities
   - Create invoices successfully

6. ✅ **Permanent Authentication**
   - Tokens persist across service restarts
   - Auto-refresh prevents auth expiry

---

## 📞 Support

If you encounter issues:
1. Check Railway logs for error details
2. Verify all environment variables are set
3. Test API endpoints individually
4. Check Zoho API console configuration
5. Ensure Railway URLs match redirect URIs exactly

**Happy deploying! 🚀**
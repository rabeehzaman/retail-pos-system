// Sample implementation of transaction history endpoints
// Add these to your server.js file

// ==================== TRANSACTION HISTORY ENDPOINTS ====================

// Get customer transaction history (invoices)
app.get('/api/customers/:customerId/invoices', async (req, res) => {
    console.log('\n========== FETCHING CUSTOMER INVOICES ==========');
    try {
        await ensureValidToken();
        
        const { customerId } = req.params;
        const { from_date, to_date, page = 1, per_page = 50, status } = req.query;
        
        console.log(`[Customer History] Customer ID: ${customerId}`);
        console.log(`[Customer History] Date range: ${from_date || 'any'} to ${to_date || 'any'}`);
        console.log(`[Customer History] Page: ${page}, Per page: ${per_page}`);
        
        // Build query parameters
        const params = {
            organization_id: process.env.ZOHO_ORGANIZATION_ID,
            customer_id: customerId,
            per_page: Math.min(per_page, 200), // Zoho max is 200
            page: page,
            sort_column: 'date',
            sort_order: 'D' // Descending (newest first)
        };
        
        // Add optional filters
        if (from_date) params.from_date = from_date;
        if (to_date) params.to_date = to_date;
        if (status) params.status = status; // draft, sent, paid, void, overdue, etc.
        
        // Fetch invoices from Zoho Books
        const response = await axios.get(`${ZOHO_BOOKS_API_URL}/invoices`, {
            headers: {
                'Authorization': `Zoho-oauthtoken ${accessToken}`
            },
            params: params
        });
        
        const invoices = response.data.invoices || [];
        
        console.log(`[Customer History] Found ${invoices.length} invoices`);
        
        // Transform invoice data for frontend
        const transformedInvoices = invoices.map(invoice => ({
            invoice_id: invoice.invoice_id,
            invoice_number: invoice.invoice_number,
            date: invoice.date,
            due_date: invoice.due_date,
            customer_name: invoice.customer_name,
            status: invoice.status,
            total: invoice.total,
            balance: invoice.balance,
            currency_code: invoice.currency_code,
            created_time: invoice.created_time,
            last_modified_time: invoice.last_modified_time,
            // Include line items summary
            line_items_count: invoice.line_items ? invoice.line_items.length : 0,
            // Payment status
            is_paid: invoice.balance === 0,
            payment_terms: invoice.payment_terms,
            // Additional useful fields
            reference_number: invoice.reference_number,
            notes: invoice.notes
        }));
        
        // Get customer details for context
        let customerDetails = null;
        if (invoices.length > 0) {
            customerDetails = {
                name: invoices[0].customer_name,
                total_invoices: response.data.page_context?.total || invoices.length,
                total_value: invoices.reduce((sum, inv) => sum + parseFloat(inv.total || 0), 0)
            };
        }
        
        console.log('========== CUSTOMER INVOICES FETCHED ==========\n');
        
        res.json({
            success: true,
            customer: customerDetails,
            invoices: transformedInvoices,
            pagination: {
                page: parseInt(page),
                per_page: parseInt(per_page),
                total: response.data.page_context?.total || invoices.length,
                has_more_page: response.data.page_context?.has_more_page || false
            }
        });
        
    } catch (error) {
        console.error('[Customer History Error]:', error.response?.data || error.message);
        res.status(500).json({ 
            error: 'Failed to fetch customer invoices',
            details: error.response?.data || error.message
        });
    }
});

// Get detailed invoice with line items
app.get('/api/invoices/:invoiceId/details', async (req, res) => {
    console.log('\n========== FETCHING INVOICE DETAILS ==========');
    try {
        await ensureValidToken();
        
        const { invoiceId } = req.params;
        console.log(`[Invoice Details] Invoice ID: ${invoiceId}`);
        
        // Fetch detailed invoice from Zoho Books
        const response = await axios.get(`${ZOHO_BOOKS_API_URL}/invoices/${invoiceId}`, {
            headers: {
                'Authorization': `Zoho-oauthtoken ${accessToken}`
            },
            params: {
                organization_id: process.env.ZOHO_ORGANIZATION_ID
            }
        });
        
        const invoice = response.data.invoice;
        
        console.log(`[Invoice Details] Invoice #${invoice.invoice_number}`);
        console.log(`[Invoice Details] Line items: ${invoice.line_items?.length || 0}`);
        
        // Transform for frontend with full details
        const detailedInvoice = {
            ...invoice,
            // Enhanced line items with product details
            line_items: invoice.line_items?.map(item => ({
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
            // Customer information
            customer_details: {
                customer_id: invoice.customer_id,
                customer_name: invoice.customer_name,
                email: invoice.email,
                billing_address: invoice.billing_address,
                shipping_address: invoice.shipping_address
            },
            // Payment information
            payment_details: {
                payment_terms: invoice.payment_terms,
                payment_terms_label: invoice.payment_terms_label,
                is_paid: invoice.balance === 0,
                payment_made: invoice.payment_made,
                payments: invoice.payments || []
            }
        };
        
        console.log('========== INVOICE DETAILS FETCHED ==========\n');
        
        res.json({
            success: true,
            invoice: detailedInvoice
        });
        
    } catch (error) {
        console.error('[Invoice Details Error]:', error.response?.data || error.message);
        res.status(500).json({ 
            error: 'Failed to fetch invoice details',
            details: error.response?.data || error.message
        });
    }
});

// Get product sales history
app.get('/api/items/:itemId/sales', async (req, res) => {
    console.log('\n========== FETCHING PRODUCT SALES HISTORY ==========');
    try {
        await ensureValidToken();
        
        const { itemId } = req.params;
        const { from_date, to_date, limit = 100 } = req.query;
        
        console.log(`[Product History] Item ID: ${itemId}`);
        console.log(`[Product History] Date range: ${from_date || 'any'} to ${to_date || 'any'}`);
        
        // First, get item details
        const itemResponse = await axios.get(`${ZOHO_BOOKS_API_URL}/items/${itemId}`, {
            headers: {
                'Authorization': `Zoho-oauthtoken ${accessToken}`
            },
            params: {
                organization_id: process.env.ZOHO_ORGANIZATION_ID
            }
        });
        
        const itemDetails = itemResponse.data.item;
        console.log(`[Product History] Product: ${itemDetails.name}`);
        
        // Fetch invoices containing this item
        // Note: Zoho doesn't have direct item_id filter, so we need to fetch and filter
        const params = {
            organization_id: process.env.ZOHO_ORGANIZATION_ID,
            per_page: 200,
            sort_column: 'date',
            sort_order: 'D'
        };
        
        if (from_date) params.from_date = from_date;
        if (to_date) params.to_date = to_date;
        
        // Fetch multiple pages if needed
        let allInvoices = [];
        let page = 1;
        let hasMore = true;
        
        while (hasMore && allInvoices.length < 1000) { // Limit to 1000 invoices for performance
            const response = await axios.get(`${ZOHO_BOOKS_API_URL}/invoices`, {
                headers: {
                    'Authorization': `Zoho-oauthtoken ${accessToken}`
                },
                params: { ...params, page }
            });
            
            if (response.data.invoices && response.data.invoices.length > 0) {
                allInvoices = allInvoices.concat(response.data.invoices);
                hasMore = response.data.page_context?.has_more_page || false;
                page++;
            } else {
                hasMore = false;
            }
        }
        
        console.log(`[Product History] Fetched ${allInvoices.length} invoices to search`);
        
        // Now fetch details for each invoice to check line items
        const salesHistory = [];
        const customerSummary = {};
        let totalQuantitySold = 0;
        let totalRevenue = 0;
        
        for (const invoice of allInvoices) {
            // Get invoice details with line items
            try {
                const detailResponse = await axios.get(`${ZOHO_BOOKS_API_URL}/invoices/${invoice.invoice_id}`, {
                    headers: {
                        'Authorization': `Zoho-oauthtoken ${accessToken}`
                    },
                    params: {
                        organization_id: process.env.ZOHO_ORGANIZATION_ID
                    }
                });
                
                const fullInvoice = detailResponse.data.invoice;
                
                // Check if this invoice contains our item
                const relevantLineItems = fullInvoice.line_items?.filter(item => item.item_id === itemId) || [];
                
                if (relevantLineItems.length > 0) {
                    relevantLineItems.forEach(lineItem => {
                        salesHistory.push({
                            invoice_id: invoice.invoice_id,
                            invoice_number: invoice.invoice_number,
                            date: invoice.date,
                            customer_id: invoice.customer_id,
                            customer_name: invoice.customer_name,
                            quantity: lineItem.quantity,
                            unit: lineItem.unit,
                            rate: lineItem.rate,
                            total: lineItem.item_total,
                            discount: lineItem.discount,
                            status: invoice.status
                        });
                        
                        // Update summaries
                        totalQuantitySold += parseFloat(lineItem.quantity || 0);
                        totalRevenue += parseFloat(lineItem.item_total || 0);
                        
                        // Track customer purchases
                        if (!customerSummary[invoice.customer_id]) {
                            customerSummary[invoice.customer_id] = {
                                customer_name: invoice.customer_name,
                                total_quantity: 0,
                                total_value: 0,
                                purchase_count: 0
                            };
                        }
                        customerSummary[invoice.customer_id].total_quantity += parseFloat(lineItem.quantity || 0);
                        customerSummary[invoice.customer_id].total_value += parseFloat(lineItem.item_total || 0);
                        customerSummary[invoice.customer_id].purchase_count++;
                    });
                }
                
                // Limit results
                if (salesHistory.length >= limit) break;
                
            } catch (detailError) {
                console.error(`[Product History] Error fetching invoice ${invoice.invoice_id}:`, detailError.message);
            }
        }
        
        // Sort sales history by date (newest first)
        salesHistory.sort((a, b) => new Date(b.date) - new Date(a.date));
        
        // Get top customers
        const topCustomers = Object.values(customerSummary)
            .sort((a, b) => b.total_value - a.total_value)
            .slice(0, 10);
        
        console.log(`[Product History] Found ${salesHistory.length} sales transactions`);
        console.log('========== PRODUCT SALES HISTORY FETCHED ==========\n');
        
        res.json({
            success: true,
            product: {
                item_id: itemDetails.item_id,
                name: itemDetails.name,
                sku: itemDetails.sku,
                unit: itemDetails.unit,
                rate: itemDetails.rate
            },
            summary: {
                total_quantity_sold: totalQuantitySold,
                total_revenue: totalRevenue,
                transaction_count: salesHistory.length,
                average_quantity_per_sale: salesHistory.length > 0 ? (totalQuantitySold / salesHistory.length).toFixed(2) : 0,
                top_customers: topCustomers
            },
            sales_history: salesHistory.slice(0, limit)
        });
        
    } catch (error) {
        console.error('[Product History Error]:', error.response?.data || error.message);
        res.status(500).json({ 
            error: 'Failed to fetch product sales history',
            details: error.response?.data || error.message
        });
    }
});

// Get customer's frequently bought items
app.get('/api/customers/:customerId/frequent-items', async (req, res) => {
    console.log('\n========== FETCHING FREQUENT ITEMS ==========');
    try {
        await ensureValidToken();
        
        const { customerId } = req.params;
        const { limit = 10 } = req.query;
        
        console.log(`[Frequent Items] Customer ID: ${customerId}`);
        
        // Fetch recent invoices for the customer
        const response = await axios.get(`${ZOHO_BOOKS_API_URL}/invoices`, {
            headers: {
                'Authorization': `Zoho-oauthtoken ${accessToken}`
            },
            params: {
                organization_id: process.env.ZOHO_ORGANIZATION_ID,
                customer_id: customerId,
                per_page: 50, // Last 50 invoices
                sort_column: 'date',
                sort_order: 'D'
            }
        });
        
        const invoices = response.data.invoices || [];
        const itemFrequency = {};
        
        // Analyze each invoice for items
        for (const invoice of invoices) {
            try {
                const detailResponse = await axios.get(`${ZOHO_BOOKS_API_URL}/invoices/${invoice.invoice_id}`, {
                    headers: {
                        'Authorization': `Zoho-oauthtoken ${accessToken}`
                    },
                    params: {
                        organization_id: process.env.ZOHO_ORGANIZATION_ID
                    }
                });
                
                const fullInvoice = detailResponse.data.invoice;
                
                // Count item frequency
                fullInvoice.line_items?.forEach(item => {
                    if (!itemFrequency[item.item_id]) {
                        itemFrequency[item.item_id] = {
                            item_id: item.item_id,
                            name: item.name,
                            sku: item.sku,
                            total_quantity: 0,
                            purchase_count: 0,
                            last_purchased: invoice.date,
                            average_quantity: 0
                        };
                    }
                    
                    itemFrequency[item.item_id].total_quantity += parseFloat(item.quantity || 0);
                    itemFrequency[item.item_id].purchase_count++;
                    
                    // Update last purchased date
                    if (new Date(invoice.date) > new Date(itemFrequency[item.item_id].last_purchased)) {
                        itemFrequency[item.item_id].last_purchased = invoice.date;
                    }
                });
                
            } catch (detailError) {
                console.error(`[Frequent Items] Error fetching invoice ${invoice.invoice_id}:`, detailError.message);
            }
        }
        
        // Calculate averages and sort by frequency
        const frequentItems = Object.values(itemFrequency)
            .map(item => ({
                ...item,
                average_quantity: (item.total_quantity / item.purchase_count).toFixed(2)
            }))
            .sort((a, b) => b.purchase_count - a.purchase_count)
            .slice(0, limit);
        
        // Get last invoice for quick reorder
        let lastInvoiceItems = [];
        if (invoices.length > 0) {
            try {
                const lastInvoiceResponse = await axios.get(`${ZOHO_BOOKS_API_URL}/invoices/${invoices[0].invoice_id}`, {
                    headers: {
                        'Authorization': `Zoho-oauthtoken ${accessToken}`
                    },
                    params: {
                        organization_id: process.env.ZOHO_ORGANIZATION_ID
                    }
                });
                
                lastInvoiceItems = lastInvoiceResponse.data.invoice.line_items?.map(item => ({
                    item_id: item.item_id,
                    name: item.name,
                    quantity: item.quantity,
                    unit: item.unit,
                    rate: item.rate
                })) || [];
                
            } catch (error) {
                console.error('[Frequent Items] Error fetching last invoice:', error.message);
            }
        }
        
        console.log(`[Frequent Items] Found ${frequentItems.length} frequently bought items`);
        console.log('========== FREQUENT ITEMS FETCHED ==========\n');
        
        res.json({
            success: true,
            customer_id: customerId,
            customer_name: invoices[0]?.customer_name || 'Unknown',
            frequent_items: frequentItems,
            last_order: {
                date: invoices[0]?.date,
                invoice_number: invoices[0]?.invoice_number,
                items: lastInvoiceItems
            },
            analysis_period: {
                invoices_analyzed: invoices.length,
                from_date: invoices[invoices.length - 1]?.date,
                to_date: invoices[0]?.date
            }
        });
        
    } catch (error) {
        console.error('[Frequent Items Error]:', error.response?.data || error.message);
        res.status(500).json({ 
            error: 'Failed to fetch frequent items',
            details: error.response?.data || error.message
        });
    }
});

// Export these endpoints by adding them to your server.js file
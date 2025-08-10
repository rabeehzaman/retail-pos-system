// Retail POS with Zoho Books Integration
const { useState, useEffect, useMemo } = React;

const TAX_RATE = 0.15; // 15% VAT for KSA
const CURRENCY = "SAR";
const BACKEND_URL = "http://localhost:3001";

function formatCurrency(n) {
  return new Intl.NumberFormat("en-SA", { style: "currency", currency: CURRENCY }).format(n);
}

function POSApp() {
  const [dark, setDark] = useState(false);
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("All");
  const [activeTab, setActiveTab] = useState("products");
  const [cart, setCart] = useState([]);
  const [viewMode, setViewMode] = useState("grid");
  
  // Zoho integration states
  const [authStatus, setAuthStatus] = useState({ authenticated: false });
  const [items, setItems] = useState([]);
  const [customers, setCustomers] = useState([]);
  const [selectedCustomer, setSelectedCustomer] = useState(null);
  const [loading, setLoading] = useState(false);
  const [syncStatus, setSyncStatus] = useState("");
  const [lastInvoice, setLastInvoice] = useState(null);
  const [cartScrollRef, setCartScrollRef] = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [currentPage, setCurrentPage] = useState('pos');
  
  // Debug helper - expose to window for console access
  React.useEffect(() => {
    window.debugPOS = {
      getCart: () => cart,
      getItems: () => items,
      testUnitConversion: (unit) => {
        const match = unit.match(/C(\d+)P/i);
        if (match) {
          return {
            unit: unit,
            piecesPerCarton: parseInt(match[1]),
            pattern: 'C{number}P format'
          };
        }
        return { unit: unit, message: 'No conversion pattern found' };
      },
      simulateInvoice: () => {
        console.log('Current cart would create invoice with:');
        cart.forEach((item, i) => {
          console.log(`Line ${i+1}: ${item.qty} ${item.unit || 'PCS'} of ${item.name} @ ${item.price} SAR = ${(item.qty * item.price).toFixed(2)} SAR`);
        });
        const subtotal = cart.reduce((sum, line) => sum + line.price * line.qty, 0);
        const tax = subtotal * 0.15;
        const total = subtotal + tax;
        console.log(`Subtotal: ${subtotal.toFixed(2)} SAR`);
        console.log(`Tax (15%): ${tax.toFixed(2)} SAR`);
        console.log(`Total: ${total.toFixed(2)} SAR`);
      },
      clearCart: () => setCart([])
    };
    
    console.log('[POS] Debug helpers loaded. Use window.debugPOS in console.');
  }, [cart, items]);

  // Check authentication status on mount
  useEffect(() => {
    checkAuthStatus();
    const params = new URLSearchParams(window.location.search);
    if (params.get('auth') === 'success') {
      setSyncStatus("Authentication successful!");
      window.history.replaceState({}, document.title, "/");
      fetchData();
    } else if (params.get('auth') === 'error') {
      setSyncStatus("Authentication failed. Please try again.");
      window.history.replaceState({}, document.title, "/");
    }
  }, []);

  // Theme management
  useEffect(() => {
    const root = document.documentElement;
    if (dark) root.classList.add("dark"); 
    else root.classList.remove("dark");
    localStorage.setItem("theme", dark ? "dark" : "light");
  }, [dark]);

  // Load theme preference
  useEffect(() => {
    const saved = localStorage.getItem("theme");
    if (saved === "dark") setDark(true);
  }, []);

  // Check auth status
  async function checkAuthStatus() {
    try {
      const response = await fetch(`${BACKEND_URL}/auth/status`);
      const data = await response.json();
      setAuthStatus(data);
      if (data.authenticated) {
        fetchData();
      }
    } catch (error) {
      console.error("Auth check failed:", error);
    }
  }

  // Login to Zoho
  async function login() {
    try {
      setLoading(true);
      const response = await fetch(`${BACKEND_URL}/auth/login`);
      const data = await response.json();
      window.location.href = data.authUrl;
    } catch (error) {
      console.error("Login failed:", error);
      setSyncStatus("Login failed. Please check backend connection.");
    } finally {
      setLoading(false);
    }
  }

  // Logout
  async function logout() {
    try {
      await fetch(`${BACKEND_URL}/auth/logout`, { method: 'POST' });
      setAuthStatus({ authenticated: false });
      setItems([]);
      setCustomers([]);
      setCart([]);
      setSyncStatus("Logged out successfully");
    } catch (error) {
      console.error("Logout failed:", error);
    }
  }

  // Fetch data from Zoho
  async function fetchData() {
    setLoading(true);
    setSyncStatus("Connecting to Zoho Books...");
    
    try {
      // Fetch items with progress updates
      setSyncStatus("Fetching items from Zoho...");
      const itemsResponse = await fetch(`${BACKEND_URL}/api/items`);
      if (itemsResponse.ok) {
        const itemsData = await itemsResponse.json();
        setItems(itemsData.items || []);
        setSyncStatus(`✅ Loaded ${itemsData.items?.length || 0} items`);
        
        // Log item count for debugging
        console.log(`[SYNC] Total items loaded: ${itemsData.items?.length || 0}`);
        if (itemsData.items?.length > 0) {
          console.log(`[SYNC] Sample items:`, itemsData.items.slice(0, 3));
        }
      } else {
        throw new Error(`Items fetch failed: ${itemsResponse.status}`);
      }
      
      // Fetch customers
      setSyncStatus("Fetching customers...");
      const customersResponse = await fetch(`${BACKEND_URL}/api/customers`);
      if (customersResponse.ok) {
        const customersData = await customersResponse.json();
        setCustomers(customersData.customers || []);
        setSyncStatus(`✅ Loaded ${itemsData.items?.length || 0} items & ${customersData.customers?.length || 0} customers`);
      }
      
    } catch (error) {
      console.error("Fetch failed:", error);
      setSyncStatus(`❌ Sync failed: ${error.message}`);
    } finally {
      setLoading(false);
      
      // Clear status after 5 seconds
      setTimeout(() => {
        setSyncStatus("");
      }, 5000);
    }
  }

  // Get unique categories
  const categories = useMemo(() => {
    const cats = new Set(["All"]);
    items.forEach(item => {
      if (item.category) cats.add(item.category);
    });
    return Array.from(cats);
  }, [items]);

  // Filter items
  const filteredItems = useMemo(() => {
    const term = search.trim().toLowerCase();
    return items.filter((it) =>
      (category === "All" || it.category === category) &&
      (term === "" || 
       it.name.toLowerCase().includes(term) || 
       (it.sku && it.sku.toLowerCase().includes(term)))
    );
  }, [search, category, items]);

  // Cart calculations
  const subtotal = useMemo(() => cart.reduce((sum, line) => sum + line.price * line.qty, 0), [cart]);
  const subtotalQty = useMemo(() => cart.reduce((sum, line) => sum + line.qty, 0), [cart]);
  const tax = useMemo(() => +(subtotal * TAX_RATE).toFixed(2), [subtotal]);
  const total = useMemo(() => +(subtotal + tax).toFixed(2), [subtotal, tax]);

  // Cart operations with unit support
  function addToCart(item, selectedUnit = null) {
    console.log('\n[CART] Adding item to cart:');
    console.log('  Item:', item.name);
    console.log('  Item stored unit:', item.storedUnit);
    console.log('  Has conversion:', item.hasConversion);
    console.log('  Pieces per carton:', item.piecesPerCarton);
    
    // Determine unit and price
    let unit, price;
    if (selectedUnit) {
      // Explicit unit selection
      unit = selectedUnit;
      price = selectedUnit === 'CTN' ? item.cartonPrice : item.piecePrice;
      console.log('  Selected unit:', selectedUnit);
    } else {
      // Default to pieces if conversion available, otherwise use stored unit
      unit = item.hasConversion ? 'PCS' : item.storedUnit;
      price = item.price; // Already set to default (piece price or carton price)
      console.log('  Default unit:', unit);
    }
    
    console.log('  Price calculation:');
    console.log('    - Unit:', unit);
    console.log('    - Piece price:', item.piecePrice, 'SAR');
    console.log('    - Carton price:', item.cartonPrice, 'SAR');
    console.log('    - Selected price:', price, 'SAR');
    
    setCart((prev) => {
      const idx = prev.findIndex((l) => l.id === item.id && l.unit === unit);
      if (idx >= 0) {
        console.log('  Updating existing cart item');
        const copy = [...prev];
        copy[idx] = { ...copy[idx], qty: copy[idx].qty + 1 };
        return copy;
      }
      
      const newCartItem = {
        id: item.id,
        name: item.name,
        price: price,
        unit: unit,
        storedUnit: item.storedUnit,  // Keep original unit for reference
        tax_percentage: item.tax_percentage || TAX_RATE * 100,
        qty: 1
      };
      
      console.log('  Adding new cart item:', newCartItem);
      
      // Auto-scroll cart to bottom when new item is added
      setTimeout(() => {
        if (cartScrollRef) {
          cartScrollRef.scrollTop = cartScrollRef.scrollHeight;
        }
      }, 100);
      
      return [...prev, newCartItem];
    });
    
    // Switch to cart on mobile
    if (window.innerWidth < 768) {
      setActiveTab("cart");
    }
  }

  function inc(id) {
    setCart((prev) => prev.map((l) => (l.id === id ? { ...l, qty: l.qty + 1 } : l)));
  }

  function dec(id) {
    setCart((prev) => prev
      .map((l) => (l.id === id ? { ...l, qty: Math.max(1, l.qty - 1) } : l))
      .filter((l) => l.qty > 0)
    );
  }

  function removeLine(id) {
    setCart((prev) => prev.filter((l) => l.id !== id));
  }

  function updatePrice(id, newPrice) {
    setCart((prev) => prev.map((l) => (l.id === id ? { ...l, price: parseFloat(newPrice) } : l)));
  }

  function updateUnit(id, newUnit) {
    setCart((prev) => prev.map((l) => (l.id === id ? { ...l, unit: newUnit } : l)));
  }

  function newSale() {
    if (cart.length === 0) return;
    if (confirm("Start a new sale? This will clear the current cart.")) {
      setCart([]);
      setSelectedCustomer(null);
      setLastInvoice(null);
    }
  }

  // Process payment and create invoice
  async function handleCharge(paymentMode = 'cash') {
    console.log('\n[CHECKOUT] Processing payment');
    console.log('  Payment mode:', paymentMode);
    console.log('  Cart items:', cart.length);
    
    if (cart.length === 0) {
      alert("Cart is empty");
      return;
    }

    setLoading(true);
    setSyncStatus("Creating invoice...");

    try {
      const lineItems = cart.map((item, index) => {
        console.log(`\n  [Cart Item ${index + 1}]`);
        console.log('    Name:', item.name);
        console.log('    Quantity:', item.qty);
        console.log('    Display Unit:', item.unit);
        console.log('    Stored Unit:', item.storedUnit);
        console.log('    Price per unit:', item.price, 'SAR');
        console.log('    Line total:', (item.qty * item.price).toFixed(2), 'SAR');
        
        // Prepare line item with proper unit handling
        const lineItem = {
          item_id: item.id,
          quantity: item.qty,
          rate: item.price,
          tax_percentage: item.tax_percentage
        };
        
        // Handle unit conversion for pieces
        if (item.unit === 'PCS') {
          // Map conversion IDs based on stored unit pattern - REQUIRED for Zoho
          const conversionIdMap = {
            'C12P': '9465000000009224',
            'C24P': '9465000000009248',
            'C50P': '9465000000009268',
            'C100P': '9465000000016005'
          };
          
          // Get the appropriate conversion ID based on stored unit
          const conversionId = conversionIdMap[item.storedUnit];
          
          if (conversionId) {
            lineItem.unit = 'PCS';
            lineItem.unit_conversion_id = conversionId;
            console.log('    Unit to send to Zoho: PCS');
            console.log(`    Added unit_conversion_id for ${item.storedUnit}: ${conversionId}`);
          } else {
            // Fallback if pattern not mapped yet
            lineItem.unit = item.storedUnit || item.unit;
            console.log(`    Warning: No conversion ID mapped for ${item.storedUnit}, using stored unit`);
          }
        } else {
          // For cartons or other units, use the stored unit
          lineItem.unit = item.storedUnit || item.unit;
          console.log('    Unit to send to Zoho:', lineItem.unit);
        }
        
        return lineItem;
      });
      
      // Add a note explaining units if any items are sold as pieces
      const hasPieceItems = cart.some(item => item.unit === 'PCS');
      const unitNote = hasPieceItems ? '\nNote: Items marked with CxxP units represent individual pieces sold from cartons.' : '';
      
      const invoiceData = {
        customer_id: selectedCustomer?.contact_id,
        line_items: lineItems,
        payment_mode: paymentMode,
        notes: `POS Sale - ${new Date().toLocaleString()}${unitNote}`
      };
      
      console.log('\n[CHECKOUT] Sending invoice data:');
      console.log(JSON.stringify(invoiceData, null, 2));

      const response = await fetch(`${BACKEND_URL}/api/invoices`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(invoiceData)
      });

      if (response.ok) {
        const result = await response.json();
        console.log('[CHECKOUT] Invoice created successfully!');
        console.log('  Invoice number:', result.invoice.invoice_number);
        console.log('  Total:', result.invoice.total, 'SAR');
        
        setLastInvoice(result.invoice);
        setSyncStatus(`✅ Invoice ${result.invoice.invoice_number} created successfully!`);
        
        // Clear cart for next sale
        setTimeout(() => {
          setCart([]);
          setSelectedCustomer(null);
        }, 2000);
      } else {
        const error = await response.json();
        console.error('[CHECKOUT] Invoice creation failed:', error);
        setSyncStatus(`Failed to create invoice: ${error.error}`);
      }
    } catch (error) {
      console.error("Invoice creation failed:", error);
      setSyncStatus("Failed to create invoice. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return React.createElement('div', { className: "h-screen w-full overflow-hidden" },
    React.createElement('div', { className: "bg-gray-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 h-full flex flex-col" },
      
      // Top Bar
      React.createElement('header', { className: "sticky top-0 z-30 w-full border-b border-slate-200/60 dark:border-slate-800 bg-white/80 dark:bg-slate-900/80 backdrop-blur" },
        React.createElement('div', { className: "max-w-7xl mx-auto px-3 py-2 flex items-center gap-2" },
          React.createElement('button', { 
            className: "p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 transition-all",
            onClick: () => setSidebarOpen(!sidebarOpen)
          }, '☰'),
          React.createElement('h1', { className: "font-semibold tracking-tight text-xl md:text-2xl" }, 'TMR POS'),
          
          // Status
          React.createElement('div', { className: "flex-1 flex items-center justify-center" },
            syncStatus && React.createElement('div', { className: "flex items-center gap-2 text-sm" },
              loading && React.createElement('span', null, '⏳'),
              React.createElement('span', null, syncStatus)
            )
          ),
          
          // Search (desktop)
          React.createElement('div', { className: "hidden md:flex items-center gap-2 w-[420px]" },
            React.createElement('div', { className: "relative flex-1" },
              React.createElement('input', {
                value: search,
                onChange: (e) => setSearch(e.target.value),
                placeholder: "Search items…",
                className: "w-full pl-9 pr-3 py-2 rounded-xl bg-slate-100 dark:bg-slate-800 outline-none focus:ring-2 ring-emerald-500"
              })
            )
          ),
          
          // Actions
          React.createElement('div', { className: "flex items-center gap-2" },
            !authStatus.authenticated ? 
              React.createElement('button', {
                onClick: login,
                disabled: loading,
                className: "px-4 py-2 rounded-xl bg-emerald-600 text-white hover:bg-emerald-700 font-medium shadow-sm transition-all"
              }, 'Connect to Zoho')
            : React.createElement(React.Fragment, null,
              React.createElement('button', {
                onClick: fetchData,
                disabled: loading,
                className: "px-3 py-2 rounded-xl bg-blue-500 text-white hover:bg-blue-600 transition-all shadow-sm font-medium",
                title: "Sync data"
              }, loading ? '⟳ Syncing...' : '🔄 Sync'),
              React.createElement('button', {
                onClick: logout,
                className: "px-3 py-2 rounded-xl bg-red-500 text-white hover:bg-red-600 transition-all shadow-sm font-medium",
                title: "Logout"
              }, '✕ Logout')
            ),
            React.createElement('button', {
              onClick: () => setDark(d => !d),
              className: "p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 transition-all"
            }, dark ? '☀️' : '🌙'),
            React.createElement('button', {
              onClick: newSale,
              className: "hidden md:inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-emerald-600 text-white hover:bg-emerald-700 font-medium shadow-sm transition-all"
            }, '🔄 New Sale')
          )
        )
      ),

      // Sidebar
      sidebarOpen && React.createElement('div', { 
        className: "fixed inset-0 z-40 flex",
        onClick: () => setSidebarOpen(false)
      },
        React.createElement('div', { 
          className: "w-64 bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 shadow-lg",
          onClick: (e) => e.stopPropagation()
        },
          React.createElement('div', { className: "p-4 border-b border-slate-200 dark:border-slate-800" },
            React.createElement('h2', { className: "font-semibold text-lg" }, 'TMR POS')
          ),
          React.createElement('nav', { className: "p-4 space-y-2" },
            React.createElement('button', {
              onClick: () => { setCurrentPage('pos'); setSidebarOpen(false); },
              className: `w-full text-left p-3 rounded-lg transition-all ${
                currentPage === 'pos' 
                  ? 'bg-emerald-100 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-400'
                  : 'hover:bg-slate-100 dark:hover:bg-slate-800'
              }`
            }, '🛒 Point of Sale'),
            React.createElement('button', {
              onClick: () => { setCurrentPage('settings'); setSidebarOpen(false); },
              className: `w-full text-left p-3 rounded-lg transition-all ${
                currentPage === 'settings' 
                  ? 'bg-emerald-100 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-400'
                  : 'hover:bg-slate-100 dark:hover:bg-slate-800'
              }`
            }, '⚙️ Settings'),
            React.createElement('button', {
              onClick: () => { setCurrentPage('reports'); setSidebarOpen(false); },
              className: `w-full text-left p-3 rounded-lg transition-all ${
                currentPage === 'reports' 
                  ? 'bg-emerald-100 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-400'
                  : 'hover:bg-slate-100 dark:hover:bg-slate-800'
              }`
            }, '📊 Reports')
          )
        )
      ),
      
      // Main Content
      React.createElement('div', { className: "flex-1 flex flex-col md:flex-row overflow-hidden" },
        
        // Products Section
        React.createElement('div', { className: `flex-1 flex flex-col scroll-independent ${activeTab === "cart" && "hidden md:flex"}` },
          
          // Categories
          React.createElement('div', { className: "p-3 border-b border-slate-200 dark:border-slate-800 flex-shrink-0" },
            React.createElement('div', { className: "flex justify-between items-center gap-2" },
              React.createElement('div', { className: "flex gap-2 overflow-x-auto pb-1 scrollbar-none flex-1" },
                categories.map(cat =>
                  React.createElement('button', {
                    key: cat,
                    onClick: () => setCategory(cat),
                    className: `px-3 py-1.5 rounded-lg whitespace-nowrap transition-all ${
                      category === cat
                        ? "bg-emerald-600 text-white"
                        : "bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700"
                    }`
                  }, cat)
                )
              ),
              React.createElement('div', { className: "flex border rounded-lg bg-slate-100 dark:bg-slate-800" },
                React.createElement('button', {
                  onClick: () => setViewMode("grid"),
                  className: `p-2 rounded-lg transition-all ${
                    viewMode === "grid" ? "bg-white dark:bg-slate-700 shadow-sm" : ""
                  }`
                }, '⊞'),
                React.createElement('button', {
                  onClick: () => setViewMode("list"),
                  className: `p-2 rounded-lg transition-all ${
                    viewMode === "list" ? "bg-white dark:bg-slate-700 shadow-sm" : ""
                  }`
                }, '☰')
              )
            )
          ),
          
          // Mobile Search
          React.createElement('div', { className: "md:hidden p-3 border-b border-slate-200 dark:border-slate-800 flex-shrink-0" },
            React.createElement('div', { className: "relative" },
              React.createElement('input', {
                value: search,
                onChange: (e) => setSearch(e.target.value),
                placeholder: "Search items…",
                className: "w-full pl-9 pr-3 py-2 rounded-xl bg-slate-100 dark:bg-slate-800 outline-none"
              })
            )
          ),
          
          // Products Grid/List
          React.createElement('div', { className: "flex-1 overflow-y-scroll overflow-x-hidden p-3" },
            !authStatus.authenticated ?
              React.createElement('div', { className: "text-center py-8" },
                React.createElement('p', { className: "text-slate-500 mb-4" }, "Connect to Zoho Books to load products"),
                React.createElement('button', {
                  onClick: login,
                  className: "px-4 py-2 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700"
                }, "Connect Now")
              )
            : filteredItems.length === 0 ?
              React.createElement('div', { className: "text-center py-8 text-slate-500" },
                items.length === 0 ? "No products loaded. Click sync to fetch from Zoho." : "No items match your search"
              )
            : React.createElement('div', { 
                className: viewMode === "grid" 
                  ? "grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3"
                  : "space-y-2"
              },
              filteredItems.map(item =>
                React.createElement('button', {
                  key: item.id,
                  onClick: () => addToCart(item),
                  className: viewMode === "grid"
                    ? "flex flex-col items-center p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-emerald-500 transition-all"
                    : "flex items-center justify-between w-full p-3 rounded-lg bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800"
                },
                  viewMode === "grid" ?
                    React.createElement(React.Fragment, null,
                      React.createElement('div', { className: "text-2xl mb-2" }, '📦'),
                      React.createElement('div', { className: "text-sm font-medium text-center" }, item.name),
                      item.sku && React.createElement('div', { className: "text-xs text-slate-500 mt-1" }, item.sku),
                      React.createElement('div', { className: "text-lg font-bold mt-2" }, 
                        `${formatCurrency(item.price)} / ${item.defaultUnit || 'PCS'}`
                      ),
                      item.hasConversion && React.createElement('div', { className: "text-xs text-slate-500 mt-1" }, 
                        `CTN: ${formatCurrency(item.cartonPrice)}`
                      ),
                      item.stock_on_hand !== undefined && 
                        React.createElement('div', { className: "text-xs text-slate-500 mt-1" }, `Stock: ${item.stock_on_hand}`)
                    )
                  : React.createElement(React.Fragment, null,
                      React.createElement('div', { className: "flex items-center gap-3" },
                        React.createElement('span', { className: "text-xl" }, '📦'),
                        React.createElement('div', { className: "text-left" },
                          React.createElement('div', { className: "font-medium" }, item.name),
                          item.sku && React.createElement('div', { className: "text-xs text-slate-500" }, item.sku)
                        )
                      ),
                      React.createElement('div', { className: "flex items-center gap-4" },
                        item.stock_on_hand !== undefined && 
                          React.createElement('span', { className: "text-sm text-slate-500" }, `Stock: ${item.stock_on_hand}`),
                        React.createElement('span', { className: "font-bold" }, 
                          `${formatCurrency(item.price)} / ${item.defaultUnit || 'PCS'}`
                        ),
                        item.hasConversion && React.createElement('span', { className: "text-xs text-slate-500" }, 
                          `(CTN: ${formatCurrency(item.cartonPrice)})`
                        ),
                        React.createElement('span', { className: "text-emerald-600" }, '+')
                      )
                    )
                )
              )
            )
          )
        ),
        
        // Cart Section
        React.createElement('div', { 
          className: `md:w-96 border-l border-slate-200 dark:border-slate-800 flex flex-col scroll-independent ${
            activeTab === "products" && "hidden md:flex"
          }`
        },
          // Customer Selection
          customers.length > 0 && React.createElement('div', { className: "p-3 border-b border-slate-200 dark:border-slate-800 flex-shrink-0" },
            React.createElement('select', {
              value: selectedCustomer?.contact_id || "",
              onChange: (e) => {
                const customer = customers.find(c => c.contact_id === e.target.value);
                setSelectedCustomer(customer || null);
              },
              className: "w-full px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-800"
            },
              React.createElement('option', { value: "" }, "Select Customer (Optional)"),
              customers.map(customer =>
                React.createElement('option', { 
                  key: customer.contact_id, 
                  value: customer.contact_id 
                }, customer.contact_name)
              )
            )
          ),
          
          // Cart Items
          React.createElement('div', { 
            className: "flex-1 overflow-y-scroll overflow-x-hidden p-3",
            ref: (el) => setCartScrollRef(el)
          },
            cart.length === 0 ?
              React.createElement('div', { className: "text-center py-8 text-slate-500" },
                React.createElement('div', { className: "text-4xl mb-3 opacity-50" }, '🛒'),
                React.createElement('p', null, "Cart is empty")
              )
            : React.createElement('div', { className: "space-y-2" },
              cart.map(line =>
                React.createElement('div', { 
                  key: line.id, 
                  className: "bg-white dark:bg-slate-900 rounded-lg p-3" 
                },
                  React.createElement('div', { className: "flex justify-between items-start mb-2" },
                    React.createElement('div', { className: "flex-1" },
                      React.createElement('div', { className: "font-medium" }, line.name),
                      React.createElement('div', { className: "flex items-center gap-2 mt-1" },
                        React.createElement('input', {
                          type: 'number',
                          step: '0.01',
                          value: line.price,
                          onChange: (e) => updatePrice(line.id, e.target.value),
                          className: "w-20 px-2 py-1 text-xs bg-slate-100 dark:bg-slate-700 rounded border-0 outline-none"
                        }),
                        React.createElement('span', { className: "text-xs text-slate-500" }, '/ '),
                        React.createElement('select', {
                          value: line.unit || 'PCS',
                          onChange: (e) => updateUnit(line.id, e.target.value),
                          className: "px-2 py-1 text-xs bg-slate-100 dark:bg-slate-700 rounded border-0 outline-none"
                        },
                          React.createElement('option', { value: 'PCS' }, 'PCS'),
                          React.createElement('option', { value: 'CTN' }, 'CTN'),
                          React.createElement('option', { value: 'KG' }, 'KG'),
                          React.createElement('option', { value: 'L' }, 'L')
                        ),
                        React.createElement('span', { className: "text-xs text-slate-500" }, `× ${line.qty}`)
                      ),
                      line.storedUnit && line.storedUnit !== line.unit && 
                        React.createElement('div', { className: "text-xs text-slate-400" }, 
                          `(Zoho unit: ${line.storedUnit})`
                        )
                    ),
                    React.createElement('button', {
                      onClick: () => removeLine(line.id),
                      className: "p-1 hover:bg-red-50 dark:hover:bg-red-900/20 rounded text-red-500"
                    }, '🗑')
                  ),
                  React.createElement('div', { className: "flex items-center justify-between" },
                    React.createElement('div', { className: "flex items-center gap-2" },
                      React.createElement('button', {
                        onClick: () => dec(line.id),
                        className: "p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800"
                      }, '−'),
                      React.createElement('span', { className: "w-8 text-center" }, line.qty),
                      React.createElement('button', {
                        onClick: () => inc(line.id),
                        className: "p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800"
                      }, '+')
                    ),
                    React.createElement('div', { className: "font-bold" }, formatCurrency(line.price * line.qty))
                  )
                )
              ),
              
              // Totals section moved here - right after cart items
              cart.length > 0 && React.createElement('div', { className: "bg-slate-50 dark:bg-slate-800 rounded-lg p-3 mt-4 space-y-2" },
                React.createElement('div', { className: "flex justify-between text-sm" },
                  React.createElement('span', null, `Subtotal (${subtotalQty} items)`),
                  React.createElement('span', null, formatCurrency(subtotal))
                ),
                React.createElement('div', { className: "flex justify-between text-sm" },
                  React.createElement('span', null, "VAT (15%)"),
                  React.createElement('span', null, formatCurrency(tax))
                ),
                React.createElement('div', { className: "flex justify-between text-lg font-bold border-t border-slate-200 dark:border-slate-600 pt-2" },
                  React.createElement('span', null, "Total"),
                  React.createElement('span', null, formatCurrency(total))
                )
              )
            )
          ),
          
          // Create Invoice Button and Last Invoice
          cart.length > 0 && React.createElement('div', { className: "border-t border-slate-200 dark:border-slate-800 p-3 flex-shrink-0" },
            // Create Invoice Button
            React.createElement('button', {
              onClick: () => handleCharge('cash'),
              disabled: loading || !authStatus.authenticated,
              className: "w-full py-3 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 disabled:opacity-50 disabled:cursor-not-allowed font-medium"
            }, "Create Invoice"),
            
            // Last Invoice
            lastInvoice && React.createElement('div', { 
              className: "mt-3 p-2 bg-green-50 dark:bg-green-900/20 rounded-lg text-sm" 
            },
              React.createElement('div', { className: "text-green-700 dark:text-green-400 font-medium" },
                `Invoice #${lastInvoice.invoice_number}`
              ),
              React.createElement('div', { className: "text-green-600 dark:text-green-500" },
                `Total: ${formatCurrency(lastInvoice.total)}`
              )
            )
          )
        )
      ),
      
        // Mobile Tab Bar
        React.createElement('div', { className: "md:hidden border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900" },
        React.createElement('div', { className: "flex" },
          React.createElement('button', {
            onClick: () => setActiveTab("products"),
            className: `flex-1 py-3 flex flex-col items-center gap-1 ${
              activeTab === "products" ? "text-emerald-600" : "text-slate-500"
            }`
          },
            React.createElement('span', null, '📦'),
            React.createElement('span', { className: "text-xs" }, "Products")
          ),
          React.createElement('button', {
            onClick: () => setActiveTab("cart"),
            className: `flex-1 py-3 flex flex-col items-center gap-1 relative ${
              activeTab === "cart" ? "text-emerald-600" : "text-slate-500"
            }`
          },
            React.createElement('span', null, '🛒'),
            React.createElement('span', { className: "text-xs" }, "Cart"),
            subtotalQty > 0 && React.createElement('span', { 
              className: "absolute top-2 right-[calc(50%-20px)] bg-red-500 text-white text-xs rounded-full w-5 h-5 flex items-center justify-center" 
            }, subtotalQty)
          )
        ),
        
        // Mobile Tab Bar
        React.createElement('div', { className: "md:hidden border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900" },
          React.createElement('div', { className: "flex" },
            React.createElement('button', {
              onClick: () => setActiveTab("products"),
              className: `flex-1 py-3 flex flex-col items-center gap-1 ${
                activeTab === "products" ? "text-emerald-600" : "text-slate-500"
              }`
            },
              React.createElement('span', null, '📦'),
              React.createElement('span', { className: "text-xs" }, "Products")
            ),
            React.createElement('button', {
              onClick: () => setActiveTab("cart"),
              className: `flex-1 py-3 flex flex-col items-center gap-1 relative ${
                activeTab === "cart" ? "text-emerald-600" : "text-slate-500"
              }`
            },
              React.createElement('span', null, '🛒'),
              React.createElement('span', { className: "text-xs" }, "Cart"),
              subtotalQty > 0 && React.createElement('span', { 
                className: "absolute top-2 right-[calc(50%-20px)] bg-red-500 text-white text-xs rounded-full w-5 h-5 flex items-center justify-center" 
              }, subtotalQty)
            )
          )
        )
      )
    )
  );
}
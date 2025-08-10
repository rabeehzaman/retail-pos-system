// Enhanced Retail POS with Zoho Books Integration & shadcn/ui Components
// Note: React hooks are already extracted in components.js

const TAX_RATE = 0.15; // 15% VAT for KSA
const CURRENCY = "SAR";
const BACKEND_URL = "https://retail-pos-backend-production.up.railway.app"; // Railway backend URL

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
  const [taxMode, setTaxMode] = useState("exclusive"); // "inclusive" or "exclusive"
  
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
  const [showCustomerPopup, setShowCustomerPopup] = useState(false);
  
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

  // Update cart prices when tax mode changes
  useEffect(() => {
    setCart(prev => prev.map(item => {
      const basePrice = item.originalPrice || item.price;
      return {
        ...item,
        originalPrice: item.originalPrice || item.price, // Ensure originalPrice is set
        price: taxMode === "inclusive" ? basePrice * (1 + TAX_RATE) : basePrice
      };
    }));
  }, [taxMode]);

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

  // Cart calculations with tax mode support
  const subtotal = useMemo(() => cart.reduce((sum, line) => sum + line.price * line.qty, 0), [cart]);
  const subtotalQty = useMemo(() => cart.reduce((sum, line) => sum + line.qty, 0), [cart]);
  
  // For tax inclusive mode, tax is already included in the subtotal
  const tax = useMemo(() => {
    if (taxMode === "inclusive") {
      // Tax is already included in prices, calculate the tax portion
      return +(subtotal - (subtotal / (1 + TAX_RATE))).toFixed(2);
    } else {
      // Tax exclusive - add tax on top
      return +(subtotal * TAX_RATE).toFixed(2);
    }
  }, [subtotal, taxMode]);
  
  const total = useMemo(() => {
    if (taxMode === "inclusive") {
      // Total is same as subtotal (tax already included)
      return +subtotal.toFixed(2);
    } else {
      // Add tax to subtotal
      return +(subtotal + tax).toFixed(2);
    }
  }, [subtotal, tax, taxMode]);

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
        price: taxMode === "inclusive" ? price * (1 + TAX_RATE) : price,
        originalPrice: price, // Keep original price for backend
        unit: unit,
        storedUnit: item.storedUnit,  // Keep original unit for reference
        tax_percentage: item.tax_percentage || TAX_RATE * 100,
        tax_id: item.tax_id || "9465000000007061", // Default to Standard Rate 15% tax ID
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

    // Check if customer is selected
    if (!selectedCustomer && customers.length > 0) {
      setShowCustomerPopup(true);
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
          rate: item.originalPrice || item.price, // Use original price for backend
          tax_id: item.tax_id || "9465000000007061" // Default to Standard Rate 15% tax ID
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
        is_inclusive_tax: taxMode === "inclusive",
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
              React.createElement(Input, {
                value: search,
                onChange: (e) => setSearch(e.target.value),
                placeholder: "Search items…",
                className: "w-full"
              })
            )
          ),
          
          // Actions  
          React.createElement('div', { className: "flex items-center gap-2" },
            !authStatus.authenticated ? 
              React.createElement(Button, {
                onClick: login,
                disabled: loading,
                className: "emerald-btn"
              }, 'Connect to Zoho')
            : React.createElement(React.Fragment, null,
              React.createElement(Button, {
                onClick: fetchData,
                disabled: loading,
                variant: "secondary",
                title: "Sync data"
              }, loading ? React.createElement(LoadingSpinner, { className: "mr-2" }) : '🔄', ' Sync'),
              React.createElement(Button, {
                onClick: logout,
                variant: "destructive",
                title: "Logout"
              }, '✕ Logout')
            ),
            React.createElement(Button, {
              onClick: () => setDark(d => !d),
              variant: "ghost",
              size: "icon"
            }, dark ? '☀️' : '🌙'),
            React.createElement(Button, {
              onClick: newSale,
              className: "hidden md:inline-flex emerald-btn"
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
            React.createElement(Button, {
              onClick: () => { setCurrentPage('pos'); setSidebarOpen(false); },
              variant: currentPage === 'pos' ? 'default' : 'ghost',
              className: 'w-full justify-start'
            }, '🛒 Point of Sale'),
            React.createElement(Button, {
              onClick: () => { setCurrentPage('settings'); setSidebarOpen(false); },
              variant: currentPage === 'settings' ? 'default' : 'ghost',
              className: 'w-full justify-start'
            }, '⚙️ Settings'),
            React.createElement(Button, {
              onClick: () => { setCurrentPage('reports'); setSidebarOpen(false); },
              variant: currentPage === 'reports' ? 'default' : 'ghost',
              className: 'w-full justify-start'
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
                  React.createElement(Button, {
                    key: cat,
                    onClick: () => setCategory(cat),
                    variant: category === cat ? "default" : "outline",
                    size: "sm",
                    className: "whitespace-nowrap"
                  }, cat)
                )
              ),
              React.createElement('div', { className: "flex border rounded-lg bg-muted p-1" },
                React.createElement(Button, {
                  onClick: () => setViewMode("grid"),
                  variant: viewMode === "grid" ? "default" : "ghost",
                  size: "icon",
                  className: "h-8 w-8"
                }, '⊞'),
                React.createElement(Button, {
                  onClick: () => setViewMode("list"),
                  variant: viewMode === "list" ? "default" : "ghost",
                  size: "icon", 
                  className: "h-8 w-8"
                }, '☰')
              )
            )
          ),
          
          // Mobile Search
          React.createElement('div', { className: "md:hidden p-3 border-b border-slate-200 dark:border-slate-800 flex-shrink-0" },
            React.createElement('div', { className: "relative" },
              React.createElement(Input, {
                value: search,
                onChange: (e) => setSearch(e.target.value),
                placeholder: "Search items…",
                className: "w-full"
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
                React.createElement(Card, {
                  key: item.id,
                  className: "cursor-pointer hover:shadow-md transition-all duration-200 border-border hover:border-primary/50 " + 
                    (viewMode === "grid" 
                      ? "flex flex-col items-center p-4" 
                      : "flex-row p-3"),
                  onClick: () => addToCart(item)
                },
                  viewMode === "grid" ? 
                    React.createElement(CardContent, { className: "flex flex-col items-center text-center p-4" },
                      React.createElement('div', { className: "text-3xl mb-3 opacity-80" }, '📦'),
                      React.createElement(CardTitle, { className: "text-sm mb-2" }, item.name),
                      item.sku && React.createElement(CardDescription, { className: "text-xs mb-2" }, item.sku),
                      React.createElement('div', { className: "text-lg font-bold text-primary mb-1" }, 
                        formatCurrency(taxMode === "inclusive" ? item.price * (1 + TAX_RATE) : item.price)
                      ),
                      React.createElement('div', { className: "text-xs text-muted-foreground mb-2" }, 
                        `per ${item.defaultUnit || 'PCS'}`
                      ),
                      item.hasConversion && React.createElement('div', { className: "text-xs text-muted-foreground" }, 
                        `Carton: ${formatCurrency(item.cartonPrice)}`
                      ),
                      item.stock_on_hand !== undefined && 
                        React.createElement(Badge, { variant: "secondary", className: "mt-2 text-xs" }, 
                          `Stock: ${item.stock_on_hand}`
                        )
                    )
                  : React.createElement(CardContent, { className: "flex items-center justify-between p-3" },
                      React.createElement('div', { className: "flex items-center gap-3" },
                        React.createElement('span', { className: "text-xl opacity-80" }, '📦'),
                        React.createElement('div', { className: "text-left" },
                          React.createElement(CardTitle, { className: "text-sm" }, item.name),
                          item.sku && React.createElement(CardDescription, { className: "text-xs" }, item.sku)
                        )
                      ),
                      React.createElement('div', { className: "flex items-center gap-4" },
                        item.stock_on_hand !== undefined && 
                          React.createElement(Badge, { variant: "outline", className: "text-xs" }, 
                            `${item.stock_on_hand} in stock`
                          ),
                        React.createElement('div', { className: "text-right" },
                          React.createElement('div', { className: "font-bold text-primary" }, 
                            formatCurrency(taxMode === "inclusive" ? item.price * (1 + TAX_RATE) : item.price)
                          ),
                          React.createElement('div', { className: "text-xs text-muted-foreground" }, 
                            `per ${item.defaultUnit || 'PCS'}`
                          ),
                          item.hasConversion && React.createElement('div', { className: "text-xs text-muted-foreground" }, 
                            `(Carton: ${formatCurrency(item.cartonPrice)})`
                          )
                        ),
                        React.createElement('div', { className: "text-lg text-emerald-600 font-bold" }, '+')
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
            React.createElement(Select, {
              value: selectedCustomer?.contact_id || "",
              onValueChange: (value) => {
                const customer = customers.find(c => c.contact_id === value);
                setSelectedCustomer(customer || null);
              }
            },
              React.createElement(SelectOption, { value: "" }, "Select Customer (Optional)"),
              customers.map(customer =>
                React.createElement(SelectOption, { 
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
                        React.createElement(Input, {
                          type: 'number',
                          step: '0.01',
                          value: line.price,
                          onChange: (e) => updatePrice(line.id, e.target.value),
                          className: "w-20 h-7 text-xs"
                        }),
                        React.createElement('span', { className: "text-xs text-muted-foreground" }, '/'),
                        React.createElement(Select, {
                          value: line.unit || 'PCS',
                          onValueChange: (value) => updateUnit(line.id, value)
                        },
                          React.createElement(SelectOption, { value: 'PCS' }, 'PCS'),
                          React.createElement(SelectOption, { value: 'CTN' }, 'CTN'),
                          React.createElement(SelectOption, { value: 'KG' }, 'KG'),
                          React.createElement(SelectOption, { value: 'L' }, 'L')
                        ),
                        React.createElement('span', { className: "text-xs text-muted-foreground" }, `× ${line.qty}`)
                      ),
                      line.storedUnit && line.storedUnit !== line.unit && 
                        React.createElement('div', { className: "text-xs text-slate-400" }, 
                          `(Zoho unit: ${line.storedUnit})`
                        )
                    ),
                    React.createElement(Button, {
                      onClick: () => removeLine(line.id),
                      variant: "ghost",
                      size: "icon",
                      className: "h-7 w-7 text-destructive hover:text-destructive hover:bg-destructive/10"
                    }, '🗑')
                  ),
                  React.createElement('div', { className: "flex items-center justify-between" },
                    React.createElement('div', { className: "flex items-center gap-1" },
                      React.createElement(Button, {
                        onClick: () => dec(line.id),
                        variant: "ghost",
                        size: "icon",
                        className: "h-7 w-7"
                      }, '−'),
                      React.createElement('span', { className: "w-8 text-center font-medium" }, line.qty),
                      React.createElement(Button, {
                        onClick: () => inc(line.id),
                        variant: "ghost", 
                        size: "icon",
                        className: "h-7 w-7"
                      }, '+')
                    ),
                    React.createElement('div', { className: "font-bold" }, formatCurrency(line.price * line.qty))
                  )
                )
              ),
              
              // Tax Mode Toggle
              cart.length > 0 && React.createElement('div', { className: "border-t border-border p-3 mt-4" },
                React.createElement('div', { className: "flex items-center justify-between mb-3" },
                  React.createElement('span', { className: "text-sm font-medium" }, "Tax Mode:"),
                  React.createElement('div', { className: "flex bg-muted rounded-lg p-1" },
                    React.createElement(Button, {
                      onClick: () => setTaxMode("exclusive"),
                      variant: taxMode === "exclusive" ? "default" : "ghost",
                      size: "sm",
                      className: "text-xs"
                    }, "Tax Exclusive"),
                    React.createElement(Button, {
                      onClick: () => setTaxMode("inclusive"),
                      variant: taxMode === "inclusive" ? "default" : "ghost",
                      size: "sm",
                      className: "text-xs"
                    }, "Tax Inclusive")
                  )
                )
              ),
              
              // Totals section moved here - right after cart items
              cart.length > 0 && React.createElement(Card, { className: "mt-4" },
                React.createElement(CardContent, { className: "p-3 space-y-2" },
                React.createElement('div', { className: "flex justify-between text-sm" },
                  React.createElement('span', null, `Subtotal (${subtotalQty} items)`),
                  React.createElement('span', null, formatCurrency(subtotal))
                ),
                React.createElement('div', { className: "flex justify-between text-sm" },
                  React.createElement('span', null, `VAT (15%) ${taxMode === "inclusive" ? "(included)" : ""}`),
                  React.createElement('span', null, formatCurrency(tax))
                ),
                  React.createElement('div', { className: "flex justify-between text-lg font-bold border-t border-border pt-2" },
                    React.createElement('span', null, "Total"),
                    React.createElement('span', null, formatCurrency(total))
                  )
                )
              )
            )
          ),
          
          // Create Invoice Button and Last Invoice
          cart.length > 0 && React.createElement('div', { className: "border-t border-border p-3 flex-shrink-0" },
            // Create Invoice Button
            React.createElement(Button, {
              onClick: () => handleCharge('cash'),
              disabled: loading || !authStatus.authenticated,
              className: "w-full h-12 emerald-btn"
            }, loading ? React.createElement(LoadingSpinner, { className: "mr-2" }) : null, "Create Invoice"),
            
            // Last Invoice
            lastInvoice && React.createElement(Card, { 
              className: "mt-3 border-green-200 bg-green-50 dark:bg-green-900/20" 
            },
              React.createElement(CardContent, { className: "p-3" },
                React.createElement('div', { className: "flex items-center justify-between" },
                  React.createElement('div', null,
                    React.createElement('div', { className: "text-green-700 dark:text-green-400 font-medium text-sm" },
                      `Invoice #${lastInvoice.invoice_number}`
                    ),
                    React.createElement('div', { className: "text-green-600 dark:text-green-500 text-xs" },
                      `Total: ${formatCurrency(lastInvoice.total)}`
                    )
                  ),
                  React.createElement(Badge, { variant: "secondary", className: "bg-green-100 text-green-700" },
                    '✓ Created'
                  )
                )
              )
            )
          )
        )
      ),
      
        // Mobile Tab Bar
        React.createElement('div', { className: "md:hidden border-t border-border bg-card" },
          React.createElement('div', { className: "flex" },
            React.createElement(Button, {
              onClick: () => setActiveTab("products"),
              variant: "ghost",
              className: `flex-1 h-16 flex-col gap-1 rounded-none ${
                activeTab === "products" ? "text-primary bg-accent" : "text-muted-foreground"
              }`
            },
              React.createElement('span', null, '📦'),
              React.createElement('span', { className: "text-xs" }, "Products")
            ),
            React.createElement(Button, {
              onClick: () => setActiveTab("cart"),
              variant: "ghost",
              className: `flex-1 h-16 flex-col gap-1 rounded-none relative ${
                activeTab === "cart" ? "text-primary bg-accent" : "text-muted-foreground"
              }`
            },
              React.createElement('span', null, '🛒'),
              React.createElement('span', { className: "text-xs" }, "Cart"),
              subtotalQty > 0 && React.createElement(Badge, { 
                className: "absolute top-2 right-[calc(50%-12px)] h-5 w-5 p-0 text-xs bg-destructive text-destructive-foreground" 
              }, subtotalQty)
            )
          )
        ),

        // Customer Selection Dialog
        React.createElement(Dialog, {
          open: showCustomerPopup,
          onOpenChange: setShowCustomerPopup
        },
          React.createElement(DialogContent, { className: "max-w-md" },
            React.createElement(DialogHeader, null,
              React.createElement(DialogTitle, null, "Select Customer"),
              React.createElement(DialogDescription, null, 
                "Please select a customer to create the invoice:"
              )
            ),
            React.createElement('div', { className: "max-h-64 overflow-y-auto space-y-2 my-4" },
              customers.map(customer =>
                React.createElement(Card, {
                  key: customer.contact_id,
                  className: "cursor-pointer hover:shadow-sm transition-all",
                  onClick: () => {
                    setSelectedCustomer(customer);
                    setShowCustomerPopup(false);
                    handleCharge('cash'); // Continue with invoice creation
                  }
                },
                  React.createElement(CardContent, { className: "p-3" },
                    React.createElement(CardTitle, { className: "text-sm" }, customer.contact_name),
                    customer.company_name && React.createElement(CardDescription, { 
                      className: "text-xs" 
                    }, customer.company_name)
                  )
                )
              )
            ),
            React.createElement(DialogFooter, null,
              React.createElement(Button, {
                onClick: () => setShowCustomerPopup(false),
                variant: "outline"
              }, "Cancel"),
              React.createElement(Button, {
                onClick: () => {
                  setSelectedCustomer(null);
                  setShowCustomerPopup(false);
                  handleCharge('cash'); // Continue with walk-in customer
                },
                className: "emerald-btn"
              }, "Walk-in Customer")
            )
          )
        )
      )
  );
}
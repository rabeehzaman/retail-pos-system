import React, { useMemo, useState, useEffect } from "react";
import { Menu, Search, ShoppingCart, Plus, Minus, Trash2, Sun, Moon, CreditCard, RefreshCcw, X, Loader2, CheckCircle, AlertCircle } from "lucide-react";

/**
 * Retail POS with Zoho Books Integration
 * Connects to backend service for secure API communication
 */

const TAX_RATE = 0.15; // 15% VAT for KSA
const CURRENCY = "SAR";
const BACKEND_URL = "https://retail-pos-backend-production.up.railway.app"; // Railway backend URL

function formatCurrency(n) {
  return new Intl.NumberFormat("en-SA", { style: "currency", currency: CURRENCY }).format(n);
}

export default function POSApp() {
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
  
  // Customer search states
  const [customerSearch, setCustomerSearch] = useState("");
  const [showCustomerDropdown, setShowCustomerDropdown] = useState(false);

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

  // Close customer dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event) {
      if (showCustomerDropdown && !event.target.closest('.customer-search-container')) {
        setShowCustomerDropdown(false);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [showCustomerDropdown]);

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

  // Fetch customers with optional search
  async function fetchCustomers(search = "") {
    try {
      const url = new URL(`${BACKEND_URL}/api/customers`);
      if (search.trim()) {
        url.searchParams.append('search', search.trim());
      }
      
      const response = await fetch(url);
      if (response.ok) {
        const data = await response.json();
        setCustomers(data.customers || []);
        return data.customers || [];
      }
    } catch (error) {
      console.error("Failed to fetch customers:", error);
    }
    return [];
  }

  // Fetch data from Zoho
  async function fetchData() {
    setLoading(true);
    setSyncStatus("Syncing with Zoho Books...");
    
    try {
      // Fetch items
      const itemsResponse = await fetch(`${BACKEND_URL}/api/items`);
      if (itemsResponse.ok) {
        const itemsData = await itemsResponse.json();
        setItems(itemsData.items || []);
        setSyncStatus(`Loaded ${itemsData.items?.length || 0} items`);
      }
      
      // Fetch customers
      await fetchCustomers();
      
      setSyncStatus("Data synced successfully!");
    } catch (error) {
      console.error("Fetch failed:", error);
      setSyncStatus("Failed to sync data. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  // Debounced customer search
  useEffect(() => {
    if (!authStatus.authenticated) return;
    
    const timeoutId = setTimeout(() => {
      if (customerSearch.trim().length >= 2 || customerSearch.trim().length === 0) {
        fetchCustomers(customerSearch);
      }
    }, 300);
    
    return () => clearTimeout(timeoutId);
  }, [customerSearch, authStatus.authenticated]);

  // Filter customers based on search
  const filteredCustomers = useMemo(() => {
    if (!customerSearch.trim()) return customers;
    
    const searchTerm = customerSearch.toLowerCase().trim();
    return customers.filter(customer => 
      customer.contact_name?.toLowerCase().includes(searchTerm) ||
      customer.company_name?.toLowerCase().includes(searchTerm) ||
      customer.email?.toLowerCase().includes(searchTerm) ||
      customer.mobile?.includes(searchTerm)
    );
  }, [customers, customerSearch]);

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

  // Cart operations
  function addToCart(item) {
    setCart((prev) => {
      const idx = prev.findIndex((l) => l.id === item.id);
      if (idx >= 0) {
        const copy = [...prev];
        copy[idx] = { ...copy[idx], qty: copy[idx].qty + 1 };
        return copy;
      }
      return [...prev, { 
        id: item.id, 
        name: item.name, 
        price: item.price,
        tax_percentage: item.tax_percentage || TAX_RATE * 100,
        qty: 1 
      }];
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
    if (cart.length === 0) {
      alert("Cart is empty");
      return;
    }

    setLoading(true);
    setSyncStatus("Creating invoice...");

    try {
      const invoiceData = {
        customer_id: selectedCustomer?.contact_id,
        line_items: cart.map(item => ({
          item_id: item.id,
          quantity: item.qty,
          rate: item.price,
          tax_percentage: item.tax_percentage
        })),
        payment_mode: paymentMode,
        notes: `POS Sale - ${new Date().toLocaleString()}`
      };

      const response = await fetch(`${BACKEND_URL}/api/invoices`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(invoiceData)
      });

      if (response.ok) {
        const result = await response.json();
        setLastInvoice(result.invoice);
        setSyncStatus(`✅ Invoice ${result.invoice.invoice_number} created successfully!`);
        
        // Clear cart for next sale
        setTimeout(() => {
          setCart([]);
          setSelectedCustomer(null);
        }, 2000);
      } else {
        const error = await response.json();
        setSyncStatus(`Failed to create invoice: ${error.error}`);
      }
    } catch (error) {
      console.error("Invoice creation failed:", error);
      setSyncStatus("Failed to create invoice. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  // Icons
  const GridIcon = () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
      <rect x="14" y="14" width="7" height="7" rx="1" />
    </svg>
  );

  const ListIcon = () => (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <line x1="8" y1="6" x2="21" y2="6" />
      <line x1="8" y1="12" x2="21" y2="12" />
      <line x1="8" y1="18" x2="21" y2="18" />
      <circle cx="3" cy="6" r="1" />
      <circle cx="3" cy="12" r="1" />
      <circle cx="3" cy="18" r="1" />
    </svg>
  );

  return (
    <div className="min-h-screen w-full">
      <div className="bg-gray-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 min-h-screen flex flex-col">
        {/* Top Bar */}
        <header className="sticky top-0 z-30 w-full border-b border-slate-200/60 dark:border-slate-800 bg-white/80 dark:bg-slate-900/80 backdrop-blur">
          <div className="max-w-7xl mx-auto px-3 py-2 flex items-center gap-2">
            <button className="p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800">
              <Menu className="w-5 h-5" />
            </button>
            <h1 className="font-semibold tracking-tight text-xl md:text-2xl">Retail POS</h1>

            {/* Status */}
            <div className="flex-1 flex items-center justify-center">
              {syncStatus && (
                <div className="flex items-center gap-2 text-sm">
                  {loading ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : syncStatus.includes("✅") ? (
                    <CheckCircle className="w-4 h-4 text-green-500" />
                  ) : syncStatus.includes("Failed") ? (
                    <AlertCircle className="w-4 h-4 text-red-500" />
                  ) : null}
                  <span>{syncStatus}</span>
                </div>
              )}
            </div>

            {/* Search */}
            <div className="hidden md:flex items-center gap-2 w-[420px]">
              <div className="relative flex-1">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search items…"
                  className="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-100 dark:bg-slate-800 outline-none focus:ring-2 ring-emerald-500"
                />
              </div>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-1 md:gap-2">
              {!authStatus.authenticated ? (
                <button
                  onClick={login}
                  disabled={loading}
                  className="px-3 py-2 rounded-xl bg-emerald-600 text-white hover:bg-emerald-700"
                >
                  Connect to Zoho
                </button>
              ) : (
                <>
                  <button
                    onClick={fetchData}
                    disabled={loading}
                    className="p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800"
                    title="Sync data"
                  >
                    <RefreshCcw className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
                  </button>
                  <button
                    onClick={logout}
                    className="p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 text-red-500"
                    title="Logout"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </>
              )}
              <button
                onClick={() => setDark((d) => !d)}
                className="p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800"
              >
                {dark ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
              </button>
              <button
                onClick={newSale}
                className="hidden md:inline-flex items-center gap-2 px-3 py-2 rounded-xl bg-slate-900 text-white dark:bg-white dark:text-slate-900 hover:opacity-90"
              >
                <RefreshCcw className="w-4 h-4" /> New Sale
              </button>
            </div>
          </div>
        </header>

        {/* Main Content */}
        <div className="flex-1 flex flex-col md:flex-row overflow-hidden">
          {/* Products Section */}
          <div className={`flex-1 flex flex-col overflow-hidden ${activeTab === "cart" && "hidden md:flex"}`}>
            {/* Categories */}
            <div className="p-3 border-b border-slate-200 dark:border-slate-800 flex-shrink-0">
              <div className="flex gap-2 overflow-x-auto pb-1 scrollbar-none">
                {categories.map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setCategory(cat)}
                    className={`px-3 py-1.5 rounded-lg whitespace-nowrap transition-all ${
                      category === cat
                        ? "bg-emerald-600 text-white"
                        : "bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700"
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            {/* Mobile Search */}
            <div className="md:hidden p-3 border-b border-slate-200 dark:border-slate-800 flex-shrink-0">
              <div className="relative">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search items…"
                  className="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-100 dark:bg-slate-800 outline-none"
                />
              </div>
            </div>

            {/* Products Grid/List */}
            <div className="flex-1 overflow-y-auto overflow-x-hidden p-3">
              {!authStatus.authenticated ? (
                <div className="text-center py-8">
                  <p className="text-slate-500 mb-4">Connect to Zoho Books to load products</p>
                  <button
                    onClick={login}
                    className="px-4 py-2 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700"
                  >
                    Connect Now
                  </button>
                </div>
              ) : filteredItems.length === 0 ? (
                <div className="text-center py-8 text-slate-500">
                  {items.length === 0 ? "No products loaded. Click sync to fetch from Zoho." : "No items match your search"}
                </div>
              ) : (
                <div className={viewMode === "grid" 
                  ? "grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3"
                  : "space-y-2"
                }>
                  {filteredItems.map((item) => (
                    <button
                      key={item.id}
                      onClick={() => addToCart(item)}
                      className={`${
                        viewMode === "grid"
                          ? "flex flex-col items-center p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-emerald-500 transition-all"
                          : "flex items-center justify-between w-full p-3 rounded-lg bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800"
                      }`}
                    >
                      {viewMode === "grid" ? (
                        <>
                          <div className="text-2xl mb-2">📦</div>
                          <div className="text-sm font-medium text-center">{item.name}</div>
                          {item.sku && <div className="text-xs text-slate-500 mt-1">{item.sku}</div>}
                          <div className="text-lg font-bold mt-2">{formatCurrency(item.price)}</div>
                          {item.stock_on_hand !== undefined && (
                            <div className="text-xs text-slate-500 mt-1">Stock: {item.stock_on_hand}</div>
                          )}
                        </>
                      ) : (
                        <>
                          <div className="flex items-center gap-3">
                            <span className="text-xl">📦</span>
                            <div className="text-left">
                              <div className="font-medium">{item.name}</div>
                              {item.sku && <div className="text-xs text-slate-500">{item.sku}</div>}
                            </div>
                          </div>
                          <div className="flex items-center gap-4">
                            {item.stock_on_hand !== undefined && (
                              <span className="text-sm text-slate-500">Stock: {item.stock_on_hand}</span>
                            )}
                            <span className="font-bold">{formatCurrency(item.price)}</span>
                            <Plus className="w-5 h-5 text-emerald-600" />
                          </div>
                        </>
                      )}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Cart Section */}
          <div className={`md:w-96 border-l border-slate-200 dark:border-slate-800 flex flex-col overflow-hidden ${
            activeTab === "products" && "hidden md:flex"
          }`}>
            {/* Customer Search & Selection */}
            {authStatus.authenticated && (
              <div className="p-3 border-b border-slate-200 dark:border-slate-800 flex-shrink-0">
                <div className="relative customer-search-container">
                  <div className="relative">
                    <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                    <input
                      type="text"
                      placeholder={selectedCustomer ? selectedCustomer.contact_name : "Search customers or use Walk-in"}
                      value={customerSearch}
                      onChange={(e) => setCustomerSearch(e.target.value)}
                      onFocus={() => setShowCustomerDropdown(true)}
                      className="w-full pl-9 pr-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-800 outline-none focus:ring-2 ring-emerald-500"
                    />
                    {selectedCustomer && (
                      <button
                        onClick={() => {
                          setSelectedCustomer(null);
                          setCustomerSearch("");
                        }}
                        className="absolute right-2 top-1/2 -translate-y-1/2 p-1 hover:bg-slate-200 dark:hover:bg-slate-700 rounded"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                  
                  {/* Customer Dropdown */}
                  {showCustomerDropdown && !selectedCustomer && (
                    <div className="absolute top-full left-0 right-0 mt-1 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg shadow-lg z-50 max-h-48 overflow-y-auto">
                      {/* Walk-in option */}
                      <button
                        onClick={() => {
                          setSelectedCustomer(null);
                          setCustomerSearch("");
                          setShowCustomerDropdown(false);
                        }}
                        className="w-full text-left px-3 py-2 hover:bg-slate-100 dark:hover:bg-slate-700 border-b border-slate-200 dark:border-slate-700"
                      >
                        <div className="font-medium">Walk-in Customer</div>
                        <div className="text-xs text-slate-500">No customer account needed</div>
                      </button>
                      
                      {/* Customer options */}
                      {filteredCustomers.slice(0, 20).map(customer => (
                        <button
                          key={customer.contact_id}
                          onClick={() => {
                            setSelectedCustomer(customer);
                            setCustomerSearch("");
                            setShowCustomerDropdown(false);
                          }}
                          className="w-full text-left px-3 py-2 hover:bg-slate-100 dark:hover:bg-slate-700"
                        >
                          <div className="font-medium">{customer.contact_name}</div>
                          {customer.company_name && (
                            <div className="text-xs text-slate-500">{customer.company_name}</div>
                          )}
                          {customer.email && (
                            <div className="text-xs text-slate-400">{customer.email}</div>
                          )}
                        </button>
                      ))}
                      
                      {filteredCustomers.length === 0 && customerSearch.length >= 2 && (
                        <div className="px-3 py-2 text-slate-500 text-sm">
                          No customers found for "{customerSearch}"
                        </div>
                      )}
                      
                      {filteredCustomers.length > 20 && (
                        <div className="px-3 py-2 text-slate-500 text-xs">
                          Showing first 20 results. Continue typing to refine...
                        </div>
                      )}
                    </div>
                  )}
                </div>
                
                {/* Selected customer info */}
                {selectedCustomer && (
                  <div className="mt-2 p-2 bg-emerald-50 dark:bg-emerald-900/20 rounded-lg text-sm">
                    <div className="font-medium text-emerald-700 dark:text-emerald-400">
                      {selectedCustomer.contact_name}
                    </div>
                    {selectedCustomer.company_name && (
                      <div className="text-emerald-600 dark:text-emerald-500">
                        {selectedCustomer.company_name}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Cart Items */}
            <div className="flex-1 overflow-y-auto overflow-x-hidden p-3">
              {cart.length === 0 ? (
                <div className="text-center py-8 text-slate-500">
                  <ShoppingCart className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p>Cart is empty</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {cart.map((line) => (
                    <div key={line.id} className="bg-white dark:bg-slate-900 rounded-lg p-3">
                      <div className="flex justify-between items-start mb-2">
                        <div className="flex-1">
                          <div className="font-medium">{line.name}</div>
                          <div className="text-sm text-slate-500">
                            {formatCurrency(line.price)} × {line.qty}
                          </div>
                        </div>
                        <button
                          onClick={() => removeLine(line.id)}
                          className="p-1 hover:bg-red-50 dark:hover:bg-red-900/20 rounded text-red-500"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => dec(line.id)}
                            className="p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800"
                          >
                            <Minus className="w-4 h-4" />
                          </button>
                          <span className="w-8 text-center">{line.qty}</span>
                          <button
                            onClick={() => inc(line.id)}
                            className="p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800"
                          >
                            <Plus className="w-4 h-4" />
                          </button>
                        </div>
                        <div className="font-bold">{formatCurrency(line.price * line.qty)}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Totals */}
            {cart.length > 0 && (
              <div className="border-t border-slate-200 dark:border-slate-800 p-3 space-y-2 flex-shrink-0">
                <div className="flex justify-between text-sm">
                  <span>Subtotal ({subtotalQty} items)</span>
                  <span>{formatCurrency(subtotal)}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span>VAT (15%)</span>
                  <span>{formatCurrency(tax)}</span>
                </div>
                <div className="flex justify-between text-lg font-bold">
                  <span>Total</span>
                  <span>{formatCurrency(total)}</span>
                </div>

                {/* Payment Buttons */}
                <div className="flex gap-2 mt-4">
                  <button
                    onClick={() => handleCharge('cash')}
                    disabled={loading || !authStatus.authenticated}
                    className="flex-1 py-3 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Cash
                  </button>
                  <button
                    onClick={() => handleCharge('card')}
                    disabled={loading || !authStatus.authenticated}
                    className="flex-1 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                  >
                    <CreditCard className="w-4 h-4" />
                    Card
                  </button>
                </div>

                {/* Last Invoice */}
                {lastInvoice && (
                  <div className="mt-3 p-2 bg-green-50 dark:bg-green-900/20 rounded-lg text-sm">
                    <div className="text-green-700 dark:text-green-400 font-medium">
                      Invoice #{lastInvoice.invoice_number}
                    </div>
                    <div className="text-green-600 dark:text-green-500">
                      Total: {formatCurrency(lastInvoice.total)}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Mobile Tab Bar */}
        <div className="md:hidden border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
          <div className="flex">
            <button
              onClick={() => setActiveTab("products")}
              className={`flex-1 py-3 flex flex-col items-center gap-1 ${
                activeTab === "products" ? "text-emerald-600" : "text-slate-500"
              }`}
            >
              <GridIcon />
              <span className="text-xs">Products</span>
            </button>
            <button
              onClick={() => setActiveTab("cart")}
              className={`flex-1 py-3 flex flex-col items-center gap-1 relative ${
                activeTab === "cart" ? "text-emerald-600" : "text-slate-500"
              }`}
            >
              <ShoppingCart className="w-5 h-5" />
              <span className="text-xs">Cart</span>
              {subtotalQty > 0 && (
                <span className="absolute top-2 right-[calc(50%-20px)] bg-red-500 text-white text-xs rounded-full w-5 h-5 flex items-center justify-center">
                  {subtotalQty}
                </span>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Add Tailwind styles */}
      <style jsx>{`
        @import url('https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css');
        
        /* Hide scrollbars for horizontal scrolling */
        .scrollbar-none {
          -ms-overflow-style: none;
          scrollbar-width: none;
        }
        .scrollbar-none::-webkit-scrollbar {
          display: none;
        }
        
        /* Ensure proper scroll containment */
        .scroll-contain {
          overscroll-behavior: contain;
        }
      `}</style>
    </div>
  );
}
import React, { useState, useEffect, useMemo } from 'react'
import { Search, ShoppingCart, Menu, Moon, Sun, RefreshCw, LogOut, Grid3x3, List, Plus, Minus, Trash2, Package, Users, CreditCard, TrendingUp, AlertCircle, Check, Settings } from 'lucide-react'
import axios from 'axios'
import { Button } from './components/ui/button'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from './components/ui/card'
import { Input } from './components/ui/input'
import { Badge } from './components/ui/badge'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './components/ui/dialog'
import { cn } from './lib/utils'
import ProductSalesHistory from './components/ProductSalesHistory'
import './App.css'

const TAX_RATE = 0.15 // 15% VAT for KSA
const CURRENCY = "SAR"
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || "https://retail-pos-backend-production.up.railway.app"

// Complete unit conversion mapping from Zoho Books - same as old frontend + complete mapping
const UNIT_CONVERSION_MAP = {
  "PIECES": "9465000000009224",
  "C12P": "9465000000009224",
  "C8P": "9465000000009228", 
  "C10P": "9465000001006966",
  "C6P": "9465000001006968",
  "C20P": "9465000001006970",
  "C60P": "9465000001006972",
  "C24P": "9465000000009248",
  "C30P": "9465000001006976",
  "C25P": "9465000001006978",
  "C18P": "9465000001006980",
  "C16P": "9465000001006982",
  "C50P": "9465000000009268",
  "C72P": "9465000001006986",
  "C4P": "9465000001006988",
  "C36P": "9465000001006990",
  "C5P": "9465000001006992",
  "C26P": "9465000001006994",
  "C48P": "9465000001006996",
  "C32P": "9465000001006998",
  "C40P": "9465000001007000",
  "C15P": "9465000001021002",
  "C100P": "9465000000016005",
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
}

function formatCurrency(n) {
  const num = parseFloat(n) || 0;
  return new Intl.NumberFormat("en-SA", { style: "currency", currency: CURRENCY }).format(num)
}

function App() {
  const [dark, setDark] = useState(false)
  const [search, setSearch] = useState("")
  const [category, setCategory] = useState("All")
  const [activeTab, setActiveTab] = useState("products")
  const [cart, setCart] = useState([])
  const [viewMode, setViewMode] = useState("grid")
  const [taxMode, setTaxMode] = useState("exclusive")
  
  // Zoho integration states
  const [authStatus, setAuthStatus] = useState({ authenticated: false })
  const [items, setItems] = useState([])
  const [customers, setCustomers] = useState([])
  const [selectedCustomer, setSelectedCustomer] = useState(null)
  const [loading, setLoading] = useState(false)
  const [syncStatus, setSyncStatus] = useState("")
  const [lastInvoice, setLastInvoice] = useState(null)
  const [editItemForm, setEditItemForm] = useState({ unit: '', price: 0, qty: 1 })
  const [cartRef, setCartRef] = useState(null)
  const [showUnitPopup, setShowUnitPopup] = useState(false)
  const [selectedItemForUnit, setSelectedItemForUnit] = useState(null)
  const [showProductSales, setShowProductSales] = useState(false)
  const [selectedProductForSales, setSelectedProductForSales] = useState(null)

  // Apply dark mode
  useEffect(() => {
    if (dark) {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }, [dark])

  // Check auth status on mount
  useEffect(() => {
    checkAuthStatus()
  }, [])

  const checkAuthStatus = async () => {
    try {
      const response = await axios.get(`${BACKEND_URL}/auth/status`)
      setAuthStatus(response.data)
      if (response.data.authenticated) {
        fetchItems()
        fetchCustomers()
      }
    } catch (error) {
      console.error('Auth check failed:', error)
      setAuthStatus({ authenticated: false })
    }
  }

  const fetchItems = async () => {
    setLoading(true)
    setSyncStatus("Fetching items from Zoho...")
    try {
      const response = await axios.get(`${BACKEND_URL}/api/items`)
      console.log('Items response:', response.data);
      console.log('First item structure:', response.data.items?.[0]);
      setItems(response.data.items || [])
      setSyncStatus(`Loaded ${response.data.items?.length || 0} items`)
    } catch (error) {
      console.error('Failed to fetch items:', error)
      setSyncStatus("Failed to load items")
    } finally {
      setLoading(false)
    }
  }

  const fetchCustomers = async () => {
    try {
      const response = await axios.get(`${BACKEND_URL}/api/customers`)
      setCustomers(response.data.customers || [])
    } catch (error) {
      console.error('Failed to fetch customers:', error)
    }
  }

  const handleLogin = () => {
    window.location.href = `${BACKEND_URL}/auth/login`
  }

  const handleLogout = async () => {
    try {
      await axios.post(`${BACKEND_URL}/auth/logout`)
      setAuthStatus({ authenticated: false })
      setItems([])
      setCustomers([])
      setCart([])
    } catch (error) {
      console.error('Logout failed:', error)
    }
  }

  const addToCart = (item) => {
    console.log('=== addToCart called ===')
    console.log('Item:', item)
    console.log('Current cart length:', cart.length)
    
    const basePrice = item.price || item.rate || item.selling_price || 0
    console.log('Base price:', basePrice)
    
    if (!item.id || !item.name || basePrice <= 0) {
      console.error('Invalid item data:', item)
      return
    }
    
    const existingItem = cart.find(i => i.id === item.id && i.unit === 'PCS')
    
    if (existingItem) {
      console.log('Updating existing item quantity')
      setCart(prev => prev.map(i => 
        i.id === item.id && i.unit === 'PCS'
          ? { ...i, qty: i.qty + 1 }
          : i
      ))
    } else {
      console.log('Adding new item to cart')
      const adjustedPrice = taxMode === "inclusive" ? basePrice * 1.15 : basePrice
      const newItem = {
        id: item.id,
        name: item.name,
        price: parseFloat(adjustedPrice),
        qty: 1,
        unit: 'PCS',
        storedUnit: item.storedUnit || 'PCS',
        tax_id: item.tax_id || "",
        tax_percentage: item.tax_percentage || 0
      }
      console.log('New cart item:', newItem)
      
      setCart(prev => {
        console.log('Previous cart:', prev)
        const newCart = [...prev, newItem]
        console.log('New cart:', newCart)
        return newCart
      })
      
      // Auto scroll to bottom of cart
      setTimeout(() => {
        if (cartRef) {
          cartRef.scrollTo({ top: cartRef.scrollHeight, behavior: 'smooth' })
        }
      }, 100)
    }
  }
  
  const addToCartWithDetails = (item, unit, qty, price, isEdit = false) => {
    console.log('Full item object:', item);
    console.log('Adding to cart:', item.id, item.name, price);
    
    if (isEdit) {
      // Update existing cart item
      setCart(prevCart => prevCart.map(i => 
        i.id === item.id && i.unit === item.unit
          ? { ...i, unit: unit, qty: qty, price: parseFloat(price) }
          : i
      ))
    } else {
      setCart(prevCart => {
        const existingItem = prevCart.find(i => i.id === item.id && i.unit === unit)
        console.log('Existing item:', existingItem);
        
        if (existingItem) {
          console.log('Updating existing item quantity');
          return prevCart.map(i => 
            i.id === item.id && i.unit === unit
              ? { ...i, qty: i.qty + qty }
              : i
          )
        } else {
          console.log('Adding new item to cart');
          const newItem = {
            id: item.id,
            name: item.name,
            price: parseFloat(price),
            qty: qty,
            unit: unit,
            storedUnit: item.storedUnit || item.unit,
            tax_id: item.tax_id || "",
            tax_percentage: item.tax_percentage || 0
          };
          console.log('New cart item:', newItem);
          
          // Auto scroll to bottom of cart
          setTimeout(() => {
            if (cartRef) {
              cartRef.scrollTo({ top: cartRef.scrollHeight, behavior: 'smooth' })
            }
          }, 100)
          
          return [...prevCart, newItem]
        }
      })
    }
    
    setShowUnitPopup(false)
    setSelectedItemForUnit(null)
  }

  const updateQuantity = (id, delta) => {
    setCart(cart.map(item => {
      if (item.id === id) {
        const newQty = Math.max(1, item.qty + delta)
        return { ...item, qty: newQty }
      }
      return item
    }))
  }

  const removeFromCart = (id, unit) => {
    setCart(cart.filter(item => !(item.id === id && item.unit === unit)))
  }

  const openEditItem = (item) => {
    setSelectedItemForUnit(item)
    setEditItemForm({
      unit: item.unit,
      price: item.price, // Use the actual cart price (already tax-adjusted if needed)
      qty: item.qty
    })
    setShowUnitPopup(true)
  }


  const clearCart = () => {
    setCart([])
    setSelectedCustomer(null)
    setLastInvoice(null)
  }

  // Download invoice PDF
  const downloadInvoice = async (invoiceId, invoiceNumber) => {
    try {
      console.log('Downloading invoice:', invoiceId);
      setSyncStatus(`Downloading invoice ${invoiceNumber}...`);
      
      const response = await axios.get(`${BACKEND_URL}/api/invoices/${invoiceId}/download`, {
        responseType: 'blob'
      });
      
      // Check if response is actually a PDF
      if (response.data.type && !response.data.type.includes('pdf')) {
        throw new Error('Response is not a PDF file');
      }
      
      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data], { type: 'application/pdf' }));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `Invoice_${invoiceNumber}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
      console.log(`Invoice ${invoiceNumber} downloaded successfully`);
      setSyncStatus(`Invoice ${invoiceNumber} downloaded successfully!`);
    } catch (error) {
      console.error('Failed to download invoice:', error);
      const errorMsg = error.response?.status === 404 
        ? 'Invoice PDF not found. It may still be generating.' 
        : error.response?.status === 401 
        ? 'Authentication error. Please refresh and try again.'
        : 'Failed to download invoice PDF. Please try again.';
      
      setSyncStatus(`Download failed: ${errorMsg}`);
      alert(errorMsg);
    }
  };

  const handleCreateInvoice = async () => {
    if (cart.length === 0) return
    
    if (!selectedCustomer) {
      alert('Please select a customer to create the invoice.')
      return
    }

    setLoading(true)
    try {
      const lineItems = cart.map(item => {
        console.log(`[Invoice] Processing item: ${item.name}`);
        console.log(`  - Display Unit: ${item.unit}`);
        console.log(`  - Stored Unit: ${item.storedUnit}`);
        console.log(`  - Price per unit: ${item.price} SAR`);
        
        // Prepare line item with proper unit handling
        const lineItem = {
          item_id: item.id,
          quantity: item.qty,
          rate: item.price,
          tax_id: item.tax_id || ""
        };
        
        // Handle unit conversion for pieces - EXPLICIT MAPPING APPROACH
        if (item.unit === 'PCS') {
          // Get the appropriate conversion ID based on stored unit
          const conversionId = UNIT_CONVERSION_MAP[item.storedUnit?.toUpperCase()];
          
          if (conversionId) {
            lineItem.unit = 'PCS';
            lineItem.unit_conversion_id = conversionId;
            console.log(`  - Unit to send to Zoho: PCS`);
            console.log(`  - Added unit_conversion_id for ${item.storedUnit}: ${conversionId}`);
          } else {
            // Fallback if pattern not mapped yet
            lineItem.unit = item.storedUnit || item.unit;
            console.log(`  - Warning: No conversion ID mapped for ${item.storedUnit}, using stored unit`);
          }
        } else if (item.unit === 'CTN') {
          // For cartons, use the stored unit (no conversion ID needed)
          lineItem.unit = item.storedUnit || item.unit;
          console.log(`  - Unit to send to Zoho: ${lineItem.unit} (CTN mode)`);
        } else {
          // For other units, use as-is
          lineItem.unit = item.unit;
          console.log(`  - Unit to send to Zoho: ${lineItem.unit}`);
        }
        
        return lineItem;
      })

      const invoiceData = {
        customer_id: selectedCustomer?.contact_id,
        line_items: lineItems,
        is_inclusive_tax: taxMode === "inclusive"
      }

      const response = await axios.post(`${BACKEND_URL}/api/invoices`, invoiceData)
      
      const invoiceData_result = {
        invoice_number: response.data.invoice.invoice_number,
        total: response.data.invoice.total,
        invoice_id: response.data.invoice.invoice_id
      };
      
      setLastInvoice(invoiceData_result)
      setSyncStatus("Invoice created successfully!")

      // Automatically download the invoice PDF after a short delay
      setTimeout(async () => {
        await downloadInvoice(invoiceData_result.invoice_id, invoiceData_result.invoice_number);
      }, 2000); // Increased delay to allow PDF generation

      clearCart()
    } catch (error) {
      console.error('Failed to create invoice:', error)
      setSyncStatus("Failed to create invoice")
    } finally {
      setLoading(false)
    }
  }

  // Computed values
  const subtotal = cart.reduce((sum, item) => sum + (item.price * item.qty), 0)
  const tax = taxMode === "inclusive" ? subtotal * (TAX_RATE / (1 + TAX_RATE)) : subtotal * TAX_RATE
  const total = taxMode === "inclusive" ? subtotal : subtotal + tax
  const subtotalQty = cart.reduce((sum, item) => sum + item.qty, 0)

  const filteredItems = useMemo(() => {
    return items.filter(item => {
      const matchesSearch = item.name.toLowerCase().includes(search.toLowerCase())
      const matchesCategory = category === "All" || item.group_name === category
      return matchesSearch && matchesCategory
    })
  }, [items, search, category])

  const categories = useMemo(() => {
    const cats = new Set(items.map(i => i.group_name).filter(Boolean))
    return ["All", ...Array.from(cats)]
  }, [items])

  return (
    <div className="h-screen bg-gray-50 dark:bg-gray-900 overflow-hidden">
      {/* Main Content - Full Width */}
      <div className="flex flex-col h-full">
        {/* Header */}
        <header className="bg-white dark:bg-gray-800 border-b px-6 py-4">
          <div className="flex items-center justify-between">
            {/* Left Section - Branding & Search */}
            <div className="flex items-center gap-6">
              <div>
                <h1 className="text-2xl font-bold gradient-text">TMR POS</h1>
                <p className="text-sm text-muted-foreground">Retail Management System</p>
              </div>
              
              <div className="flex items-center gap-4">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    type="text"
                    placeholder="Search products..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    className="pl-10 w-80"
                  />
                </div>
                
                {/* Tax Mode Toggle - moved here with clear selection */}
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">Tax Mode:</span>
                  <div className="flex border-2 border-gray-300 dark:border-gray-600 rounded-lg p-1 bg-white dark:bg-gray-800">
                    <Button
                      size="sm"
                      onClick={() => setTaxMode("exclusive")}
                      className={`text-xs px-3 py-2 rounded-md transition-all font-medium ${
                        taxMode === "exclusive" 
                          ? 'bg-blue-600 text-white shadow-md ring-2 ring-blue-300' 
                          : 'bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-gray-600'
                      }`}
                    >
                      {taxMode === "exclusive" && "✓ "}Tax Exclusive
                    </Button>
                    <Button
                      size="sm"
                      onClick={() => setTaxMode("inclusive")}
                      className={`text-xs px-3 py-2 rounded-md transition-all ml-1 font-medium ${
                        taxMode === "inclusive" 
                          ? 'bg-green-600 text-white shadow-md ring-2 ring-green-300' 
                          : 'bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-gray-600'
                      }`}
                    >
                      {taxMode === "inclusive" && "✓ "}Tax Inclusive
                    </Button>
                  </div>
                </div>
              </div>
            </div>

            {/* Right Section - Customer Selection & Actions */}
            <div className="flex items-center gap-4">
              {/* Customer Selection - no default */}
              <div className="flex items-center gap-2">
                <label className="text-sm font-medium">Customer:</label>
                <select 
                  value={selectedCustomer?.contact_id || ""}
                  onChange={(e) => {
                    const customer = customers.find(c => c.contact_id === e.target.value);
                    setSelectedCustomer(customer || null);
                  }}
                  className="px-3 py-2 border rounded-md bg-background min-w-[200px]"
                >
                  <option value="">Select Customer (Required)</option>
                  {customers.map(customer => (
                    <option key={customer.contact_id} value={customer.contact_id}>
                      {customer.contact_name}
                    </option>
                  ))}
                </select>
              </div>


              {/* Zoho Status */}
              {authStatus.authenticated ? (
                <div className="flex items-center gap-2 text-sm">
                  <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
                  <span className="text-muted-foreground">Connected</span>
                </div>
              ) : (
                <Button className="emerald-btn" onClick={handleLogin}>
                  Connect to Zoho
                </Button>
              )}

              <Button
                variant="ghost"
                size="icon"
                onClick={() => setDark(!dark)}
              >
                {dark ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
              </Button>
              
              <Button
                variant="ghost"
                size="icon"
                onClick={fetchItems}
                disabled={loading || !authStatus.authenticated}
              >
                <RefreshCw className={cn("h-5 w-5", loading && "animate-spin")} />
              </Button>

              <Button
                variant="success"
                onClick={clearCart}
                disabled={cart.length === 0}
              >
                <RefreshCw className="mr-2 h-4 w-4" />
                New Sale
              </Button>

            </div>
          </div>

          {syncStatus && (
            <div className="mt-2">
              <Badge variant="outline">{syncStatus}</Badge>
            </div>
          )}
          
        </header>

        {/* Content Area */}
        <div className="flex-1 flex overflow-hidden">
          {/* Products Grid - Wider */}
          <div className="flex-1 overflow-y-auto p-6">
            {/* Category Tabs */}
            <div className="mb-6 flex items-center justify-between">
              <div className="flex gap-2 overflow-x-auto pb-2">
                {categories.map(cat => (
                  <Button
                    key={cat}
                    variant={category === cat ? "default" : "outline"}
                    size="sm"
                    onClick={() => setCategory(cat)}
                  >
                    {cat}
                  </Button>
                ))}
              </div>

              <div className="flex gap-2">
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => setViewMode("grid")}
                >
                  <Grid3x3 className={cn("h-4 w-4", viewMode === "grid" && "text-primary")} />
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => setViewMode("list")}
                >
                  <List className={cn("h-4 w-4", viewMode === "list" && "text-primary")} />
                </Button>
              </div>
            </div>

            {/* Products */}
            {!authStatus.authenticated ? (
              <Card className="glass-card">
                <CardContent className="flex flex-col items-center justify-center py-12">
                  <AlertCircle className="h-12 w-12 text-muted-foreground mb-4" />
                  <p className="text-lg font-medium mb-2">Connect to Zoho Books</p>
                  <p className="text-sm text-muted-foreground mb-4">Load your products and start selling</p>
                  <Button className="emerald-btn" onClick={handleLogin}>
                    Connect Now
                  </Button>
                </CardContent>
              </Card>
            ) : filteredItems.length === 0 ? (
              <Card className="glass-card">
                <CardContent className="flex flex-col items-center justify-center py-12">
                  <Package className="h-12 w-12 text-muted-foreground mb-4" />
                  <p className="text-lg font-medium">No products found</p>
                  <p className="text-sm text-muted-foreground">Try adjusting your search or filters</p>
                </CardContent>
              </Card>
            ) : viewMode === "grid" ? (
              <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 xl:grid-cols-8 gap-4">
                {filteredItems.map(item => (
                  <Card 
                    key={item.id} 
                    className="product-card cursor-pointer"
                    onClick={(e) => {
                      e.preventDefault()
                      e.stopPropagation()
                      addToCart(item)
                    }}
                  >
                    <CardHeader className="pb-2">
                      <div className="flex items-start justify-between">
                        <CardTitle className="text-sm font-medium line-clamp-3 flex-1 mr-2">
                          {item.name}
                        </CardTitle>
                        {item.stock_on_hand && (
                          <Badge 
                            variant={item.stock_on_hand > 10 ? "success" : "warning"}
                            className="text-xs shrink-0"
                          >
                            {item.stock_on_hand}
                          </Badge>
                        )}
                      </div>
                    </CardHeader>
                    <CardContent className="pt-0">
                      <div className="flex items-end justify-between">
                        <div className="text-right flex-1">
                          <div className="text-lg font-bold text-primary">
                            {formatCurrency(taxMode === "inclusive" ? (item.price || item.rate || item.selling_price || 0) * 1.15 : (item.price || item.rate || item.selling_price || 0))}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            per PCS
                          </div>
                        </div>
                        <div className="flex gap-1">
                          <Button 
                            size="icon" 
                            variant="ghost" 
                            className="h-8 w-8"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedProductForSales(item);
                              setShowProductSales(true);
                            }}
                            title="View Sales History"
                          >
                            <TrendingUp className="h-4 w-4" />
                          </Button>
                          <Button size="icon" variant="ghost" className="h-8 w-8">
                            <Plus className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            ) : (
              <div className="space-y-1">
                {filteredItems.map(item => (
                  <div 
                    key={item.id}
                    className="flex items-center justify-between p-3 bg-white dark:bg-gray-800 border rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer transition-colors"
                    onClick={(e) => {
                      e.preventDefault()
                      e.stopPropagation()
                      addToCart(item)
                    }}
                  >
                    <div className="flex items-center flex-1">
                      <div className="flex-1 min-w-0">
                        <h3 className="font-medium text-sm truncate">{item.name}</h3>
                      </div>
                    </div>
                    
                    <div className="flex items-center gap-4">
                      <Button 
                        size="icon" 
                        variant="ghost" 
                        className="h-7 w-7"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedProductForSales(item);
                          setShowProductSales(true);
                        }}
                        title="View Sales History"
                      >
                        <TrendingUp className="h-3 w-3" />
                      </Button>
                      {item.stock_on_hand && (
                        <Badge 
                          variant={item.stock_on_hand > 10 ? "success" : "warning"} 
                          className="text-xs"
                        >
                          {item.stock_on_hand}
                        </Badge>
                      )}
                      <div className="text-right">
                        <div className="font-bold text-primary">
                          {formatCurrency(taxMode === "inclusive" ? (item.price || item.rate || item.selling_price || 0) * 1.15 : (item.price || item.rate || item.selling_price || 0))}
                        </div>
                        <div className="text-xs text-muted-foreground">per PCS</div>
                      </div>
                      <Button size="icon" variant="ghost" className="h-8 w-8 hover:bg-primary hover:text-white">
                        <Plus className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Cart Sidebar - Narrower */}
          <div className="w-80 bg-white dark:bg-gray-800 border-l flex flex-col">
            <div className="p-4 border-b">
              <div className="flex items-center justify-between">
                <h3 className="font-semibold flex items-center gap-2">
                  <ShoppingCart className="h-5 w-5" />
                  Cart ({subtotalQty})
                </h3>
                {cart.length > 0 && (
                  <Button variant="ghost" size="sm" onClick={clearCart}>
                    Clear
                  </Button>
                )}
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-4" ref={setCartRef}>
              {cart.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
                  <ShoppingCart className="h-12 w-12 mb-4 opacity-50" />
                  <p>Cart is empty</p>
                  <p className="text-sm mt-2">Add items to get started</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {cart.map(item => (
                    <Card key={`${item.id}-${item.unit}`} className="shimmer">
                      <CardContent className="p-3">
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex-1">
                            <p className="font-medium text-sm">{item.name}</p>
                            <p className="text-xs text-muted-foreground">
                              {formatCurrency(item.price)} × {item.qty} ({item.unit})
                            </p>
                          </div>
                          <div className="flex gap-1">
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-6 w-6"
                              onClick={() => openEditItem(item)}
                            >
                              <Settings className="h-3 w-3" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-6 w-6"
                              onClick={() => removeFromCart(item.id, item.unit)}
                            >
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          </div>
                        </div>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-1">
                            <Button
                              variant="outline"
                              size="icon"
                              className="h-7 w-7"
                              onClick={() => updateQuantity(item.id, -1)}
                            >
                              <Minus className="h-3 w-3" />
                            </Button>
                            <span className="w-8 text-center text-sm">{item.qty}</span>
                            <Button
                              variant="outline"
                              size="icon"
                              className="h-7 w-7"
                              onClick={() => updateQuantity(item.id, 1)}
                            >
                              <Plus className="h-3 w-3" />
                            </Button>
                          </div>
                          <span className="font-semibold">
                            {formatCurrency(item.price * item.qty)}
                          </span>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </div>

            {cart.length > 0 && (
              <div className="border-t p-4 space-y-3">

                {/* Totals */}
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Subtotal</span>
                    <span>{formatCurrency(subtotal)}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>VAT (15%){taxMode === "inclusive" ? " (included)" : ""}</span>
                    <span>{formatCurrency(tax)}</span>
                  </div>
                  <div className="flex justify-between text-lg font-bold pt-2 border-t">
                    <span>Total</span>
                    <span>{formatCurrency(total)}</span>
                  </div>
                </div>

                {/* Checkout Button */}
                <Button
                  className="w-full emerald-btn"
                  size="lg"
                  onClick={handleCreateInvoice}
                  disabled={loading || !authStatus.authenticated || !selectedCustomer}
                >
                  {loading ? (
                    <>
                      <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                      Processing...
                    </>
                  ) : (
                    <>
                      <CreditCard className="mr-2 h-4 w-4" />
                      Create Invoice
                    </>
                  )}
                </Button>

                {/* Last Invoice - Simple notification with download */}
                {lastInvoice && (
                  <Card className="bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200">
                    <CardContent className="p-3">
                      <div className="flex items-center justify-between mb-2">
                        <div>
                          <p className="text-sm font-medium text-emerald-700 dark:text-emerald-400">
                            Invoice #{lastInvoice.invoice_number}
                          </p>
                          <p className="text-xs text-emerald-600 dark:text-emerald-500">
                            Total: {formatCurrency(lastInvoice.total)}
                          </p>
                        </div>
                        <Badge variant="success">
                          <Check className="mr-1 h-3 w-3" />
                          Created
                        </Badge>
                      </div>
                      <Button
                        onClick={() => downloadInvoice(lastInvoice.invoice_id, lastInvoice.invoice_number)}
                        size="sm"
                        className="w-full text-xs bg-emerald-600 text-white hover:bg-emerald-700"
                        disabled={loading}
                      >
                        📥 Download PDF
                      </Button>
                    </CardContent>
                  </Card>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      
      {/* Unit Selection Dialog */}
      <Dialog open={showUnitPopup} onOpenChange={() => setShowUnitPopup(false)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>
              {cart.some(i => i.id === selectedItemForUnit?.id) ? 'Edit Cart Item' : 'Add Item to Cart'}
            </DialogTitle>
            <DialogDescription>
              {selectedItemForUnit && `Configure ${selectedItemForUnit.name} ${cart.some(i => i.id === selectedItemForUnit?.id) ? 'in your cart' : 'before adding to cart'}`}
            </DialogDescription>
          </DialogHeader>
          
          {selectedItemForUnit && (
            <div className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">Unit</label>
                <div className="flex gap-2">
                  <Button
                    variant={editItemForm.unit === 'PCS' ? 'default' : 'outline'}
                    onClick={() => {
                      const basePrice = selectedItemForUnit.price || selectedItemForUnit.rate || selectedItemForUnit.selling_price || 0
                      const adjustedPrice = taxMode === "inclusive" ? basePrice * 1.15 : basePrice
                      setEditItemForm({...editItemForm, unit: 'PCS', price: adjustedPrice})
                    }}
                    className="flex-1"
                  >
                    PCS
                  </Button>
                  <Button
                    variant={editItemForm.unit === 'CTN' ? 'default' : 'outline'}
                    onClick={() => {
                      const basePrice = selectedItemForUnit.price || selectedItemForUnit.rate || selectedItemForUnit.selling_price || 0
                      const adjustedPrice = taxMode === "inclusive" ? (basePrice * 12) * 1.15 : basePrice * 12
                      setEditItemForm({...editItemForm, unit: 'CTN', price: adjustedPrice})
                    }}
                    className="flex-1"
                  >
                    CTN
                  </Button>
                </div>
              </div>
              
              <div className="space-y-2">
                <label className="text-sm font-medium">Quantity</label>
                <Input
                  type="number"
                  min="1"
                  value={editItemForm.qty}
                  onChange={(e) => setEditItemForm({...editItemForm, qty: parseInt(e.target.value) || 1})}
                />
              </div>
              
              <div className="space-y-2">
                <label className="text-sm font-medium">Price per Unit (SAR)</label>
                <Input
                  type="number"
                  step="0.01"
                  value={editItemForm.price}
                  onChange={(e) => setEditItemForm({...editItemForm, price: parseFloat(e.target.value) || 0})}
                  placeholder="0.00"
                />
              </div>
              
              <div className="bg-muted p-3 rounded-lg">
                <div className="text-sm font-medium mb-1">Summary:</div>
                <div className="text-sm text-muted-foreground">
                  {editItemForm.qty} {editItemForm.unit} × {formatCurrency(editItemForm.price)} = {formatCurrency(editItemForm.qty * editItemForm.price)}
                </div>
              </div>
            </div>
          )}
          
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowUnitPopup(false)}>
              Cancel
            </Button>
            <Button 
              onClick={() => {
                const isEditingExisting = cart.some(i => i.id === selectedItemForUnit.id)
                addToCartWithDetails(selectedItemForUnit, editItemForm.unit || 'PCS', editItemForm.qty || 1, editItemForm.price || 0, isEditingExisting)
              }}
              disabled={!editItemForm.unit || !editItemForm.price}
            >
              {cart.some(i => i.id === selectedItemForUnit?.id) ? 'Update Cart' : 'Add to Cart'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Product Sales History Modal */}
      <ProductSalesHistory 
        isOpen={showProductSales}
        onClose={() => {
          setShowProductSales(false);
          setSelectedProductForSales(null);
        }}
        product={selectedProductForSales}
        selectedCustomer={selectedCustomer}
        backendUrl={BACKEND_URL}
      />
    </div>
  )
}

export default App
import React, { useState, useEffect, useMemo } from 'react'
import { Search, ShoppingCart, Menu, Moon, Sun, RefreshCw, LogOut, Grid3x3, List, Plus, Minus, Trash2, Package, Users, CreditCard, TrendingUp, AlertCircle, Check, Settings, Filter, X } from 'lucide-react'
import axios from 'axios'
import { Button } from './components/ui/button'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from './components/ui/card'
import { Input } from './components/ui/input'
import { Badge } from './components/ui/badge'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './components/ui/dialog'
import { cn } from './lib/utils'
import { MobileNavigation } from './components/MobileNavigation'
import { ProductGrid } from './components/ProductGrid'
import { MobileCart } from './components/MobileCart'
import './App.css'

const TAX_RATE = 0.15
const CURRENCY = "SAR"
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || "https://retail-pos-backend-production.up.railway.app"

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
  const num = parseFloat(n) || 0
  return new Intl.NumberFormat("en-SA", { style: "currency", currency: CURRENCY }).format(num)
}

function AppMobile() {
  const [dark, setDark] = useState(false)
  const [search, setSearch] = useState("")
  const [category, setCategory] = useState("All")
  const [activeTab, setActiveTab] = useState("products")
  const [cart, setCart] = useState([])
  const [viewMode, setViewMode] = useState("grid")
  const [taxMode, setTaxMode] = useState("exclusive")
  const [showSearch, setShowSearch] = useState(false)
  const [showFilters, setShowFilters] = useState(false)
  const [isMobile, setIsMobile] = useState(false)
  
  // Zoho integration states
  const [authStatus, setAuthStatus] = useState({ authenticated: false })
  const [items, setItems] = useState([])
  const [customers, setCustomers] = useState([])
  const [selectedCustomer, setSelectedCustomer] = useState(null)
  const [loading, setLoading] = useState(false)
  const [syncStatus, setSyncStatus] = useState("")
  const [lastInvoice, setLastInvoice] = useState(null)
  const [showCheckoutDialog, setShowCheckoutDialog] = useState(false)
  const [showSettingsDialog, setShowSettingsDialog] = useState(false)

  // Check if mobile
  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 768)
    }
    checkMobile()
    window.addEventListener('resize', checkMobile)
    return () => window.removeEventListener('resize', checkMobile)
  }, [])

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
      console.error('Failed to check auth status:', error)
    }
  }

  const handleLogin = () => {
    window.open(`${BACKEND_URL}/auth/login`, '_blank', 'width=600,height=700')
    
    const checkAuth = setInterval(async () => {
      try {
        const response = await axios.get(`${BACKEND_URL}/auth/status`)
        if (response.data.authenticated) {
          setAuthStatus(response.data)
          clearInterval(checkAuth)
          fetchItems()
          fetchCustomers()
        }
      } catch (error) {
        console.error('Auth check failed:', error)
      }
    }, 2000)

    setTimeout(() => clearInterval(checkAuth), 60000)
  }

  const fetchItems = async () => {
    setLoading(true)
    setSyncStatus("Syncing products...")
    try {
      const response = await axios.get(`${BACKEND_URL}/api/items`)
      setItems(response.data.items || [])
      setSyncStatus(`Synced ${response.data.items?.length || 0} products`)
      setTimeout(() => setSyncStatus(""), 3000)
    } catch (error) {
      console.error('Failed to fetch items:', error)
      setSyncStatus("Sync failed")
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

  const categories = useMemo(() => {
    const cats = new Set(["All"])
    items.forEach(item => {
      if (item.category_name) cats.add(item.category_name)
    })
    return Array.from(cats)
  }, [items])

  const filteredItems = useMemo(() => {
    return items.filter(item => {
      const matchesSearch = !search || 
        item.name?.toLowerCase().includes(search.toLowerCase()) ||
        item.sku?.toLowerCase().includes(search.toLowerCase())
      const matchesCategory = category === "All" || item.category_name === category
      return matchesSearch && matchesCategory
    })
  }, [items, search, category])

  const addToCart = (item) => {
    const existingItem = cart.find(i => i.id === item.id)
    if (existingItem) {
      setCart(cart.map(i => 
        i.id === item.id 
          ? { ...i, quantity: i.quantity + 1 }
          : i
      ))
    } else {
      setCart([...cart, {
        ...item,
        quantity: 1,
        price: item.price || item.rate || item.selling_price || 0
      }])
    }
  }

  const updateCartQuantity = (itemId, quantity) => {
    if (quantity <= 0) {
      setCart(cart.filter(i => i.id !== itemId))
    } else {
      setCart(cart.map(i => 
        i.id === itemId ? { ...i, quantity } : i
      ))
    }
  }

  const removeFromCart = (itemId) => {
    setCart(cart.filter(i => i.id !== itemId))
  }

  const clearCart = () => {
    setCart([])
    setLastInvoice(null)
  }

  const handleCheckout = async () => {
    if (!selectedCustomer || cart.length === 0) return
    
    setShowCheckoutDialog(true)
    
    try {
      const lineItems = cart.map(item => ({
        item_id: item.item_id,
        quantity: item.quantity,
        rate: item.price,
        unit: UNIT_CONVERSION_MAP[item.unit] || UNIT_CONVERSION_MAP.PIECES
      }))

      const subtotal = cart.reduce((sum, item) => sum + (item.price * item.quantity), 0)
      
      const response = await axios.post(`${BACKEND_URL}/api/invoices`, {
        customer_id: selectedCustomer,
        line_items: lineItems,
        is_inclusive_tax: taxMode === "inclusive"
      })

      setLastInvoice(response.data)
      clearCart()
      setShowCheckoutDialog(false)
      setActiveTab('products')
    } catch (error) {
      console.error('Checkout failed:', error)
      alert('Checkout failed. Please try again.')
      setShowCheckoutDialog(false)
    }
  }

  const renderContent = () => {
    switch (activeTab) {
      case 'products':
        return (
          <>
            {/* Mobile Header */}
            <div className="sticky top-0 z-40 bg-background border-b">
              <div className="p-4">
                <div className="flex items-center gap-2">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                      type="search"
                      placeholder="Search products..."
                      className="pl-9 h-10"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                    />
                  </div>
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => setShowFilters(!showFilters)}
                  >
                    <Filter className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => {
                      if (authStatus.authenticated) {
                        fetchItems()
                        fetchCustomers()
                      }
                    }}
                    disabled={loading || !authStatus.authenticated}
                  >
                    <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
                  </Button>
                </div>

                {showFilters && (
                  <div className="mt-3 flex gap-2 overflow-x-auto pb-2">
                    {categories.map(cat => (
                      <Button
                        key={cat}
                        variant={category === cat ? "default" : "outline"}
                        size="sm"
                        onClick={() => setCategory(cat)}
                        className="shrink-0"
                      >
                        {cat}
                      </Button>
                    ))}
                  </div>
                )}

                {syncStatus && (
                  <div className="mt-2">
                    <Badge variant="outline" className="text-xs">{syncStatus}</Badge>
                  </div>
                )}
              </div>
            </div>

            {/* Products Grid */}
            <div className="flex-1 overflow-y-auto pb-20">
              {!authStatus.authenticated ? (
                <div className="p-4">
                  <Card className="glass-card">
                    <CardContent className="flex flex-col items-center justify-center py-12">
                      <AlertCircle className="h-12 w-12 text-muted-foreground mb-4" />
                      <p className="text-lg font-medium mb-2">Connect to Zoho Books</p>
                      <p className="text-sm text-muted-foreground mb-4 text-center">Load your products and start selling</p>
                      <Button className="emerald-btn" onClick={handleLogin}>
                        Connect Now
                      </Button>
                    </CardContent>
                  </Card>
                </div>
              ) : (
                <div className="py-4">
                  <ProductGrid
                    items={filteredItems}
                    onAddToCart={addToCart}
                    formatCurrency={formatCurrency}
                    taxMode={taxMode}
                    viewMode={viewMode}
                    isMobile={true}
                  />
                </div>
              )}
            </div>
          </>
        )

      case 'cart':
        return (
          <div className="h-full">
            <MobileCart
              cart={cart}
              onUpdateQuantity={updateCartQuantity}
              onRemoveItem={removeFromCart}
              onCheckout={handleCheckout}
              formatCurrency={formatCurrency}
              taxMode={taxMode}
              selectedCustomer={selectedCustomer}
              onClose={() => setActiveTab('products')}
              isFullScreen={true}
            />
          </div>
        )

      case 'customers':
        return (
          <div className="p-4">
            <h2 className="text-lg font-semibold mb-4">Select Customer</h2>
            <select
              value={selectedCustomer || ""}
              onChange={(e) => setSelectedCustomer(e.target.value)}
              className="w-full px-3 py-2 border rounded-md bg-background"
            >
              <option value="">Select Customer (Required)</option>
              {customers.map(customer => (
                <option key={customer.contact_id} value={customer.contact_id}>
                  {customer.contact_name}
                </option>
              ))}
            </select>
            {selectedCustomer && (
              <Card className="mt-4">
                <CardContent className="pt-6">
                  <div className="flex items-center gap-2 text-sm">
                    <Check className="h-4 w-4 text-emerald-500" />
                    <span>Customer selected</span>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        )

      case 'settings':
        return (
          <div className="p-4 space-y-4">
            <h2 className="text-lg font-semibold mb-4">Settings</h2>
            
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Display</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm">Dark Mode</span>
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => setDark(!dark)}
                  >
                    {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
                  </Button>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">View Mode</span>
                  <div className="flex gap-2">
                    <Button
                      variant={viewMode === "grid" ? "default" : "outline"}
                      size="icon"
                      onClick={() => setViewMode("grid")}
                    >
                      <Grid3x3 className="h-4 w-4" />
                    </Button>
                    <Button
                      variant={viewMode === "list" ? "default" : "outline"}
                      size="icon"
                      onClick={() => setViewMode("list")}
                    >
                      <List className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Tax Settings</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Tax Mode</span>
                  <select
                    value={taxMode}
                    onChange={(e) => setTaxMode(e.target.value)}
                    className="px-3 py-2 border rounded-md bg-background"
                  >
                    <option value="exclusive">Exclusive</option>
                    <option value="inclusive">Inclusive</option>
                  </select>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Zoho Integration</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {authStatus.authenticated ? (
                  <>
                    <div className="flex items-center gap-2 text-sm">
                      <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
                      <span>Connected to Zoho Books</span>
                    </div>
                    <Button
                      variant="outline"
                      className="w-full"
                      onClick={() => {
                        setAuthStatus({ authenticated: false })
                        setItems([])
                        setCustomers([])
                      }}
                    >
                      <LogOut className="mr-2 h-4 w-4" />
                      Disconnect
                    </Button>
                  </>
                ) : (
                  <Button className="w-full emerald-btn" onClick={handleLogin}>
                    Connect to Zoho Books
                  </Button>
                )}
              </CardContent>
            </Card>

            {lastInvoice && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Last Invoice</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm">Invoice #{lastInvoice.invoice_number}</p>
                  <p className="text-xs text-muted-foreground">Total: {formatCurrency(lastInvoice.total)}</p>
                </CardContent>
              </Card>
            )}
          </div>
        )

      default:
        return null
    }
  }

  return (
    <div className="flex flex-col h-screen bg-background">
      {renderContent()}
      
      {isMobile && (
        <MobileNavigation
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          cartItemCount={cart.length}
        />
      )}

      <Dialog open={showCheckoutDialog} onOpenChange={setShowCheckoutDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Processing Checkout</DialogTitle>
            <DialogDescription>
              Creating invoice in Zoho Books...
            </DialogDescription>
          </DialogHeader>
          <div className="flex items-center justify-center py-6">
            <RefreshCw className="h-8 w-8 animate-spin text-primary" />
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}

export default AppMobile
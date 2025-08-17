import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react'
import { Search, ShoppingCart, Menu, Moon, Sun, RefreshCw, LogOut, Grid3x3, List, Plus, Minus, Trash2, Package, Users, CreditCard, TrendingUp, AlertCircle, Check, Settings, Filter, X, WifiOff, Wifi } from 'lucide-react'
import axios from 'axios'
import { Button } from './components/ui/button'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from './components/ui/card'
import { Input } from './components/ui/input'
import { Badge } from './components/ui/badge'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './components/ui/dialog'
import { cn } from './lib/utils'
import { MobileNavigation } from './components/MobileNavigation'
import { VirtualProductGrid } from './components/VirtualProductGrid'
import { MobileCart } from './components/MobileCart'
import ProductSalesHistory from './components/ProductSalesHistory'
import Toast from './components/Toast'
import InvoiceSuccessModal from './components/InvoiceSuccessModal'
import { useAutoAuth } from './hooks/useAutoAuth'
import { useOfflineSync } from './hooks/useOfflineSync'
import * as localStorage from './utils/localStorage'
import * as db from './utils/db'
import { registerServiceWorker } from './utils/offline'
import './App.css'

const TAX_RATE = 0.15
const CURRENCY = "SAR"
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || "https://retail-pos-backend-production.up.railway.app"

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
}

function formatCurrency(n) {
  const num = parseFloat(n) || 0
  return new Intl.NumberFormat("en-SA", { style: "currency", currency: CURRENCY }).format(num)
}

function AppMobile() {
  // Load saved preferences
  const [dark, setDark] = useState(() => localStorage.getTheme())
  const [search, setSearch] = useState("")
  const [category, setCategory] = useState("All")
  const [activeTab, setActiveTab] = useState("products")
  const [cart, setCart] = useState([])
  const [viewMode, setViewMode] = useState(() => localStorage.getViewMode())
  const [taxMode, setTaxMode] = useState(() => localStorage.getTaxMode())
  const [showSearch, setShowSearch] = useState(false)
  const [showFilters, setShowFilters] = useState(false)
  const [isMobile, setIsMobile] = useState(false)
  const [selectedCustomer, setSelectedCustomer] = useState(null)
  const [lastInvoice, setLastInvoice] = useState(null)
  const [showCheckoutDialog, setShowCheckoutDialog] = useState(false)
  const [showSettingsDialog, setShowSettingsDialog] = useState(false)
  const [items, setItems] = useState([])
  const [customers, setCustomers] = useState([])
  const [editItemForm, setEditItemForm] = useState({ unit: '', price: 0, qty: 1 })
  const [showUnitPopup, setShowUnitPopup] = useState(false)
  const [selectedItemForUnit, setSelectedItemForUnit] = useState(null)
  const [showProductSales, setShowProductSales] = useState(false)
  const [selectedProductForSales, setSelectedProductForSales] = useState(null)
  const gridContainerRef = useRef(null)
  const [containerDimensions, setContainerDimensions] = useState({ width: 0, height: 0 })
  
  // Branch selection state
  const [branches, setBranches] = useState([])
  const [selectedBranch, setSelectedBranch] = useState(() => localStorage.getSelectedBranch())
  
  // Toast and Success Modal state
  const [toast, setToast] = useState(null)
  const [showSuccessModal, setShowSuccessModal] = useState(false)
  const [isDownloading, setIsDownloading] = useState(false)
  
  // Use performance optimization hooks
  const { authStatus, authError, login, logout, checkStoredAuth } = useAutoAuth(BACKEND_URL)
  const { 
    isOffline, 
    syncStatus, 
    lastSyncTime, 
    pendingChanges,
    syncProducts, 
    syncCustomers, 
    saveTransaction, 
    syncData 
  } = useOfflineSync(BACKEND_URL)

  // Initialize app
  useEffect(() => {
    const initializeApp = async () => {
      // Check database version and clear if needed
      const dbVersion = window.localStorage.getItem('db_version')
      if (dbVersion !== '2') {
        console.log('Clearing old database schema...')
        try {
          await db.clearAllData() // Clear all IndexedDB data
        } catch (err) {
          console.error('Failed to clear old data:', err)
        }
        window.localStorage.setItem('db_version', '2')
      }
      
      // Initialize IndexedDB first and wait for it
      await db.initDB()
      
      // Register service worker for PWA
      registerServiceWorker()
      
      // Load saved cart from IndexedDB
      const savedCart = await db.getCart()
      if (savedCart && savedCart.length > 0) {
        setCart(savedCart)
      }
      
      // Load last customer
      const lastCustomer = localStorage.getLastCustomer()
      if (lastCustomer) {
        setSelectedCustomer(lastCustomer.contact_id)
      }
      
      // Now that IndexedDB is ready, check stored auth
      // This ensures auth tokens can be retrieved properly
      await checkStoredAuth()
    }
    
    initializeApp()
  }, [checkStoredAuth])
  
  // Check if mobile and measure container
  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 768)
      
      if (gridContainerRef.current) {
        const rect = gridContainerRef.current.getBoundingClientRect()
        setContainerDimensions({
          width: rect.width || window.innerWidth,
          height: rect.height || window.innerHeight - 200
        })
      }
    }
    checkMobile()
    window.addEventListener('resize', checkMobile)
    return () => window.removeEventListener('resize', checkMobile)
  }, [])

  // Apply and save dark mode
  useEffect(() => {
    if (dark) {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
    localStorage.saveTheme(dark)
  }, [dark])
  
  // Save preferences when they change
  useEffect(() => {
    localStorage.saveViewMode(viewMode)
  }, [viewMode])
  
  useEffect(() => {
    localStorage.saveTaxMode(taxMode)
  }, [taxMode])
  
  // Save cart to IndexedDB when it changes
  useEffect(() => {
    if (cart.length > 0) {
      db.saveCart(cart)
    } else {
      db.clearCart()
    }
  }, [cart])
  
  // Save selected customer
  useEffect(() => {
    if (selectedCustomer) {
      const customer = customers.find(c => c.contact_id === selectedCustomer)
      if (customer) {
        localStorage.saveLastCustomer(customer)
      }
    }
  }, [selectedCustomer, customers])

  // Load data when authenticated
  useEffect(() => {
    if (authStatus.authenticated) {
      loadData()
    }
  }, [authStatus.authenticated])
  
  const fetchBranches = useCallback(async () => {
    try {
      const response = await axios.get(`${BACKEND_URL}/api/branches`)
      if (response.data.success) {
        setBranches(response.data.branches || [])
        console.log('Branches loaded:', response.data.branches?.length || 0)
      }
    } catch (error) {
      console.error('Failed to fetch branches:', error)
      setBranches([]) // Set empty array if branches not available
    }
  }, [])
  
  const loadData = useCallback(async () => {
    // Load products (from cache or API)
    const products = await syncProducts()
    setItems(products || [])
    
    // Load customers (from cache or API)
    const customerList = await syncCustomers()
    setCustomers(customerList || [])
    
    // Load branches (only if authenticated)
    if (authStatus.authenticated) {
      await fetchBranches()
    }
  }, [syncProducts, syncCustomers, authStatus.authenticated, fetchBranches])
  
  const handleLogin = useCallback(async () => {
    const success = await login()
    if (success) {
      loadData()
    }
  }, [login, loadData])
  
  const handleLogout = useCallback(async () => {
    await logout()
    setItems([])
    setCustomers([])
    setCart([])
    setSelectedCustomer(null)
    setBranches([])
    setSelectedBranch(null)
    await db.clearAllData()
  }, [logout])

  // Download invoice PDF
  const downloadInvoice = useCallback(async (invoiceId, invoiceNumber) => {
    try {
      console.log('Downloading invoice:', invoiceId)
      setIsDownloading(true)
      
      const response = await axios.get(`${BACKEND_URL}/api/invoices/${invoiceId}/download`, {
        responseType: 'blob'
      })
      
      // Check if response is actually a PDF
      if (response.data.type && !response.data.type.includes('pdf')) {
        throw new Error('Response is not a PDF file')
      }
      
      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data], { type: 'application/pdf' }))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `Invoice_${invoiceNumber}.pdf`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
      
      console.log(`Invoice ${invoiceNumber} downloaded successfully`)
      
      // Show success toast
      setToast({
        message: `Invoice ${invoiceNumber} downloaded successfully!`,
        type: 'success',
        duration: 3000
      })
      
    } catch (error) {
      console.error('Failed to download invoice:', error)
      const errorMsg = error.response?.status === 404 
        ? 'Invoice PDF not found. It may still be generating.' 
        : error.response?.status === 401 
        ? 'Authentication error. Please refresh and try again.'
        : 'Failed to download invoice PDF. Please try again.'
      
      // Show error toast
      setToast({
        message: errorMsg,
        type: 'error',
        duration: 5000
      })
    } finally {
      setIsDownloading(false)
    }
  }, [BACKEND_URL])

  const showToast = useCallback((message, type = 'info', duration = 5000) => {
    setToast({ message, type, duration })
  }, [])

  const categories = useMemo(() => {
    const cats = new Set(["All"])
    items.forEach(item => {
      if (item.category_name) cats.add(item.category_name)
    })
    return Array.from(cats)
  }, [items])

  const filteredItems = useMemo(() => {
    return items.filter(item => {
      const searchTerm = String(search || '').toLowerCase()
      const matchesSearch = !searchTerm || 
        item.name?.toLowerCase().includes(searchTerm) ||
        item.sku?.toLowerCase().includes(searchTerm)
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
        item_id: item.item_id || item.id,
        price: item.price || item.rate || item.selling_price || 0
      }])
    }
  }

  const addToCartWithDetails = (item, unit, qty, price, isEdit = false) => {
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
        
        if (existingItem) {
          return prevCart.map(i => 
            i.id === item.id && i.unit === unit
              ? { ...i, qty: i.qty + qty }
              : i
          )
        } else {
          const newItem = {
            id: item.id,
            item_id: item.item_id || item.id,
            name: item.name,
            price: parseFloat(price),
            qty: qty,
            unit: unit,
            storedUnit: item.storedUnit || item.unit,
            tax_id: item.tax_id || "",
            tax_percentage: item.tax_percentage || 0
          }
          
          return [...prevCart, newItem]
        }
      })
    }
    
    setShowUnitPopup(false)
    setSelectedItemForUnit(null)
  }

  const handleLongPressProduct = (item) => {
    // Set up the unit form with default values for new item
    setSelectedItemForUnit(item)
    const basePrice = item.price || item.rate || item.selling_price || 0
    const adjustedPrice = taxMode === "inclusive" ? basePrice * 1.15 : basePrice
    setEditItemForm({
      unit: 'PCS',
      price: adjustedPrice,
      qty: 1
    })
    setShowUnitPopup(true)
  }

  const handleProductSales = (item) => {
    setSelectedProductForSales(item)
    setShowProductSales(true)
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
      const lineItems = cart.map(item => {
        const lineItem = {
          item_id: item.item_id,
          quantity: item.qty || item.quantity || 1,
          rate: item.price,
          tax_id: item.tax_id || "9465000000007061" // Default tax ID
        };
        
        // Handle unit conversion similar to desktop version
        if (item.unit === 'PCS') {
          // Get the appropriate conversion ID based on stored unit
          const conversionId = UNIT_CONVERSION_MAP[item.storedUnit?.toUpperCase()];
          
          if (conversionId) {
            lineItem.unit = 'PCS';
            lineItem.unit_conversion_id = conversionId;
          } else {
            // Fallback if pattern not mapped yet
            lineItem.unit = item.storedUnit || item.unit;
          }
        } else if (item.unit === 'CTN') {
          // For cartons, use the stored unit (no conversion ID needed)
          lineItem.unit = item.storedUnit || item.unit;
        } else {
          // For other units, use as-is
          lineItem.unit = item.unit;
        }
        
        return lineItem;
      })

      const subtotal = cart.reduce((sum, item) => sum + (item.price * (item.qty || item.quantity || 1)), 0)
      
      const transaction = {
        customer_id: selectedCustomer,
        line_items: lineItems,
        is_inclusive_tax: taxMode === "inclusive",
        branch_id: selectedBranch?.branch_id || null
      }
      
      // Use offline-capable save transaction
      const result = await saveTransaction(transaction)
      
      if (result.pending) {
        // Transaction saved offline
        const pendingInvoice = {
          invoice_number: `PENDING-${result.localId}`,
          total: subtotal * (taxMode === "inclusive" ? 1 : 1.15),
          pending: true
        }
        setLastInvoice(pendingInvoice)
        
        // Show success modal for offline invoice
        setShowCheckoutDialog(false)
        setShowSuccessModal(true)
        
        // Show toast notification
        showToast('Invoice saved offline! Will sync when connected.', 'warning', 4000)
        
      } else {
        // Online invoice created successfully
        const invoiceData = {
          invoice_id: result.invoice?.invoice_id || result.invoice_id,
          invoice_number: result.invoice?.invoice_number || result.invoice_number,
          total: result.invoice?.total || result.total,
          status: result.invoice?.status || result.status
        }
        setLastInvoice(invoiceData)
        
        // Show success modal
        setShowCheckoutDialog(false)
        setShowSuccessModal(true)
        
        // Show success toast
        showToast(`Invoice ${invoiceData.invoice_number} created successfully!`, 'success', 3000)
        
        // Auto-download PDF after 2 seconds (like desktop)
        setTimeout(async () => {
          if (invoiceData.invoice_id) {
            await downloadInvoice(invoiceData.invoice_id, invoiceData.invoice_number)
          }
        }, 2000)
      }
      
      clearCart()
    } catch (error) {
      console.error('Checkout failed:', error)
      setShowCheckoutDialog(false)
      
      // Show error toast instead of alert
      const errorMessage = isOffline 
        ? 'Transaction saved offline. Will sync when connection is restored.' 
        : 'Checkout failed. Please try again.'
      
      showToast(errorMessage, 'error', 5000)
    }
  }

  const handleNewSale = useCallback(() => {
    setShowSuccessModal(false)
    setActiveTab('products')
    setLastInvoice(null)
  }, [])

  const handleSuccessDownload = useCallback(() => {
    if (lastInvoice && !lastInvoice.pending) {
      downloadInvoice(lastInvoice.invoice_id, lastInvoice.invoice_number)
    }
  }, [lastInvoice, downloadInvoice])

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
                        syncData()
                      }
                    }}
                    disabled={syncStatus === 'syncing' || !authStatus.authenticated}
                  >
                    <RefreshCw className={cn("h-4 w-4", syncStatus === 'syncing' && "animate-spin")} />
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

                <div className="mt-2 flex items-center gap-2">
                  {isOffline ? (
                    <Badge variant="destructive" className="text-xs">
                      <WifiOff className="h-3 w-3 mr-1" />
                      Offline Mode
                    </Badge>
                  ) : (
                    <Badge variant="success" className="text-xs">
                      <Wifi className="h-3 w-3 mr-1" />
                      Online
                    </Badge>
                  )}
                  {pendingChanges > 0 && (
                    <Badge variant="warning" className="text-xs">
                      {pendingChanges} pending
                    </Badge>
                  )}
                  {syncStatus === 'syncing' && (
                    <Badge variant="outline" className="text-xs">Syncing...</Badge>
                  )}
                </div>
              </div>
            </div>

            {/* Products Grid */}
            <div className="flex-1 overflow-y-auto pb-16">
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
                <div className="py-4" ref={gridContainerRef}>
                  <VirtualProductGrid
                    items={filteredItems}
                    onAddToCart={addToCart}
                    formatCurrency={formatCurrency}
                    taxMode={taxMode}
                    viewMode={viewMode}
                    isMobile={true}
                    isLoading={syncStatus === 'syncing' && items.length === 0}
                    containerHeight={containerDimensions.height || 600}
                    containerWidth={containerDimensions.width || window.innerWidth}
                    onLongPress={handleLongPressProduct}
                    onProductSales={handleProductSales}
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
          <div className="flex-1 overflow-y-auto pb-16">
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
          </div>
        )

      case 'settings':
        return (
          <div className="flex-1 overflow-y-auto pb-16">
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

            {/* Branch Selection Card */}
            {branches.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Branch/Location</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Current Branch</span>
                  </div>
                  <select
                    value={selectedBranch?.branch_id || ''}
                    onChange={(e) => {
                      const branchId = e.target.value
                      const branch = branches.find(b => b.branch_id === branchId) || null
                      setSelectedBranch(branch)
                      localStorage.saveSelectedBranch(branch)
                    }}
                    className="w-full px-3 py-2 border rounded-md bg-background"
                  >
                    <option value="">No Branch Selected</option>
                    {branches.map(branch => (
                      <option key={branch.branch_id} value={branch.branch_id}>
                        {branch.branch_name}
                      </option>
                    ))}
                  </select>
                  {selectedBranch && (
                    <div className="p-2 bg-muted rounded-md">
                      <p className="text-xs text-muted-foreground">
                        Selected: {selectedBranch.branch_name}
                      </p>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

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
                      onClick={handleLogout}
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
                  {lastInvoice.pending && (
                    <Badge variant="warning" className="mt-2 text-xs">
                      Pending Sync
                    </Badge>
                  )}
                </CardContent>
              </Card>
            )}
            
            {lastSyncTime && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Sync Status</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm">Last synced: {new Date(lastSyncTime).toLocaleTimeString()}</p>
                  {pendingChanges > 0 && (
                    <p className="text-xs text-muted-foreground mt-1">
                      {pendingChanges} transactions pending
                    </p>
                  )}
                </CardContent>
              </Card>
            )}
            </div>
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
                  onFocus={(e) => e.target.select()}
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
                  onFocus={(e) => e.target.select()}
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

      {/* Invoice Success Modal */}
      <InvoiceSuccessModal
        isOpen={showSuccessModal}
        onClose={() => setShowSuccessModal(false)}
        invoice={lastInvoice}
        formatCurrency={formatCurrency}
        onDownload={handleSuccessDownload}
        onNewSale={handleNewSale}
        isDownloading={isDownloading}
      />

      {/* Toast Notification */}
      {toast && (
        <Toast
          message={toast.message}
          type={toast.type}
          duration={toast.duration}
          onClose={() => setToast(null)}
        />
      )}
    </div>
  )
}

export default AppMobile
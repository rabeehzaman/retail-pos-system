import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react'
import { Search, ShoppingCart, Menu, Moon, Sun, RefreshCw, LogOut, Grid3x3, List, Plus, Minus, Trash2, Package, Users, CreditCard, TrendingUp, AlertCircle, Check, Settings, WifiOff, Wifi } from 'lucide-react'
import axios from 'axios'
import { Button } from './components/ui/button'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from './components/ui/card'
import { Input } from './components/ui/input'
import { Badge } from './components/ui/badge'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './components/ui/dialog'
import { cn } from './lib/utils'
import ProductSalesHistory from './components/ProductSalesHistory'
import { VirtualProductGrid } from './components/VirtualProductGrid'
import { useOfflineSync } from './hooks/useOfflineSync'
import * as db from './utils/db'
import * as localStorage from './utils/localStorage'
import { registerServiceWorker } from './utils/offline'
import './App.css'

const TAX_RATE = 0.15 // 15% VAT for KSA
const CURRENCY = "SAR"
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || "https://retail-pos-backend-production.up.railway.app"

// Complete unit conversion mapping from Zoho Books - same as old frontend + complete mapping
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
  const num = parseFloat(n) || 0;
  return new Intl.NumberFormat("en-SA", { style: "currency", currency: CURRENCY }).format(num)
}

function App() {
  // Load saved preferences
  const [dark, setDark] = useState(() => localStorage.getTheme())
  const [search, setSearch] = useState("")
  const [debouncedSearch, setDebouncedSearch] = useState("")
  const [category, setCategory] = useState("All")
  const [activeTab, setActiveTab] = useState("products")
  const [cart, setCart] = useState([])
  const [viewMode, setViewMode] = useState(() => localStorage.getViewMode())
  const [taxMode, setTaxMode] = useState(() => localStorage.getTaxMode())
  
  // Zoho integration states
  const [authStatus, setAuthStatus] = useState({ authenticated: false })
  const [items, setItems] = useState([])
  const [customers, setCustomers] = useState([])
  const [selectedCustomer, setSelectedCustomer] = useState(null)
  const [loading, setLoading] = useState(false)
  const [syncStatusLocal, setSyncStatusLocal] = useState("")
  const [lastInvoice, setLastInvoice] = useState(null)
  const [editItemForm, setEditItemForm] = useState({ unit: '', price: 0, qty: 1 })
  const [cartRef, setCartRef] = useState(null)
  const [showUnitPopup, setShowUnitPopup] = useState(false)
  const [selectedItemForUnit, setSelectedItemForUnit] = useState(null)
  const [showProductSales, setShowProductSales] = useState(false)
  const [selectedProductForSales, setSelectedProductForSales] = useState(null)

  // UI state
  const [isCartCollapsed, setIsCartCollapsed] = useState(false)
  const [selectedProductIndex, setSelectedProductIndex] = useState(-1)

  // Container dimensions for virtual scrolling
  const gridContainerRef = useRef(null)
  const [containerDimensions, setContainerDimensions] = useState({ width: 0, height: 0 })
  const [isMobile, setIsMobile] = useState(false)

  // Offline sync hook
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

  // Initialize app with IndexedDB
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
      
      // Check auth status after IndexedDB is ready
      checkAuthStatus()
    }
    
    initializeApp()
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
    if (selectedCustomer && customers.length > 0) {
      const customer = customers.find(c => c.contact_id === selectedCustomer)
      if (customer) {
        localStorage.saveLastCustomer(customer)
      }
    }
  }, [selectedCustomer, customers])

  // Check if mobile and measure container dimensions
  useEffect(() => {
    const measureContainer = () => {
      setIsMobile(window.innerWidth < 768)
      
      if (gridContainerRef.current) {
        const rect = gridContainerRef.current.getBoundingClientRect()
        const cartWidth = isCartCollapsed ? 60 : 320 // Collapsed vs expanded cart width
        setContainerDimensions({
          width: rect.width || window.innerWidth - cartWidth - 48, // Account for cart + padding
          height: rect.height || window.innerHeight - 300 // Reserve space for header
        })
      }
    }
    
    measureContainer()
    window.addEventListener('resize', measureContainer)
    return () => window.removeEventListener('resize', measureContainer)
  }, [isCartCollapsed])

  // Debounce search input
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(search)
    }, 300)
    
    return () => clearTimeout(timer)
  }, [search])


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
    setSyncStatusLocal("Fetching items from Zoho...")
    try {
      const items = await syncProducts()
      console.log('Items loaded:', items);
      console.log('First item structure:', items?.[0]);
      setItems(items || [])
      setSyncStatusLocal(`Loaded ${items?.length || 0} items`)
    } catch (error) {
      console.error('Failed to fetch items:', error)
      setSyncStatusLocal("Failed to load items")
    } finally {
      setLoading(false)
    }
  }

  const fetchCustomers = async () => {
    try {
      const customers = await syncCustomers()
      setCustomers(customers || [])
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

  const addToCart = useCallback((item) => {
    console.log('=== addToCart called ===')
    console.log('Item:', item)
    
    const basePrice = item.price || item.rate || item.selling_price || 0
    console.log('Base price:', basePrice)
    
    if (!item.id || !item.name || basePrice <= 0) {
      console.error('Invalid item data:', item)
      return
    }
    
    setCart(prev => {
      const existingItem = prev.find(i => i.id === item.id && i.unit === 'PCS')
      
      if (existingItem) {
        console.log('Updating existing item quantity')
        return prev.map(i => 
          i.id === item.id && i.unit === 'PCS'
            ? { ...i, qty: i.qty + 1 }
            : i
        )
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
        
        // Auto scroll to bottom of cart
        requestAnimationFrame(() => {
          if (cartRef) {
            cartRef.scrollTo({ top: cartRef.scrollHeight, behavior: 'smooth' })
          }
        })
        
        return [...prev, newItem]
      }
    })
  }, [taxMode, cartRef])
  
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

  const updateQuantity = useCallback((id, delta) => {
    setCart(prev => prev.map(item => {
      if (item.id === id) {
        const newQty = Math.max(1, item.qty + delta)
        return { ...item, qty: newQty }
      }
      return item
    }))
  }, [])

  const removeFromCart = useCallback((id, unit) => {
    setCart(prev => prev.filter(item => !(item.id === id && item.unit === unit)))
  }, [])

  const openEditItem = (item) => {
    setSelectedItemForUnit(item)
    setEditItemForm({
      unit: item.unit,
      price: item.price, // Use the actual cart price (already tax-adjusted if needed)
      qty: item.qty
    })
    setShowUnitPopup(true)
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


  const clearCart = useCallback(() => {
    setCart([])
    setSelectedCustomer(null)
    setLastInvoice(null)
  }, [])

  // Download invoice PDF
  const downloadInvoice = async (invoiceId, invoiceNumber) => {
    try {
      console.log('Downloading invoice:', invoiceId);
      setSyncStatusLocal(`Downloading invoice ${invoiceNumber}...`);
      
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
      setSyncStatusLocal(`Invoice ${invoiceNumber} downloaded successfully!`);
    } catch (error) {
      console.error('Failed to download invoice:', error);
      const errorMsg = error.response?.status === 404 
        ? 'Invoice PDF not found. It may still be generating.' 
        : error.response?.status === 401 
        ? 'Authentication error. Please refresh and try again.'
        : 'Failed to download invoice PDF. Please try again.';
      
      setSyncStatusLocal(`Download failed: ${errorMsg}`);
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
        customer_id: selectedCustomer,
        line_items: lineItems,
        is_inclusive_tax: taxMode === "inclusive"
      }

      // Use offline sync for invoice creation
      const result = await saveTransaction(invoiceData)
      
      if (result.pending) {
        setSyncStatusLocal("Invoice queued for sync when online")
        setLastInvoice({
          invoice_number: `PENDING-${result.localId}`,
          total: cart.reduce((sum, item) => sum + (item.price * item.qty), 0),
          invoice_id: null,
          pending: true
        })
      } else {
        const invoiceData_result = {
          invoice_number: result.invoice.invoice_number,
          total: result.invoice.total,
          invoice_id: result.invoice.invoice_id
        };
        
        setLastInvoice(invoiceData_result)
        setSyncStatusLocal("Invoice created successfully!")

        // Automatically download the invoice PDF after a short delay
        setTimeout(async () => {
          await downloadInvoice(invoiceData_result.invoice_id, invoiceData_result.invoice_number);
        }, 2000);
      }

      clearCart()
    } catch (error) {
      console.error('Failed to create invoice:', error)
      setSyncStatusLocal("Failed to create invoice")
    } finally {
      setLoading(false)
    }
  }

  // Computed values - memoized for performance
  const subtotal = useMemo(() => 
    cart.reduce((sum, item) => sum + (item.price * item.qty), 0), [cart])
  
  const tax = useMemo(() => 
    taxMode === "inclusive" ? subtotal * (TAX_RATE / (1 + TAX_RATE)) : subtotal * TAX_RATE, 
    [subtotal, taxMode])
  
  const total = useMemo(() => 
    taxMode === "inclusive" ? subtotal : subtotal + tax, 
    [subtotal, tax, taxMode])
  
  const subtotalQty = useMemo(() => 
    cart.reduce((sum, item) => sum + item.qty, 0), [cart])

  const filteredItems = useMemo(() => {
    if (!items || items.length === 0) return []
    
    return items.filter(item => {
      const searchTerm = String(debouncedSearch || '').toLowerCase()
      const matchesSearch = !searchTerm || 
        item.name?.toLowerCase().includes(searchTerm) ||
        item.sku?.toLowerCase().includes(searchTerm)
      const matchesCategory = category === "All" || item.group_name === category
      return matchesSearch && matchesCategory
    })
  }, [items, debouncedSearch, category])

  const categories = useMemo(() => {
    if (!items || items.length === 0) return ["All"]
    const cats = new Set(items.map(i => i.group_name).filter(Boolean))
    return ["All", ...Array.from(cats).sort()]
  }, [items])

  // Keyboard navigation - placed after filteredItems definition
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Only handle keyboard navigation when not typing in inputs
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') {
        return
      }

      const maxIndex = filteredItems.length - 1
      
      switch (e.key) {
        case 'ArrowRight':
          e.preventDefault()
          setSelectedProductIndex(prev => prev < maxIndex ? prev + 1 : 0)
          break
        case 'ArrowLeft':
          e.preventDefault()
          setSelectedProductIndex(prev => prev > 0 ? prev - 1 : maxIndex)
          break
        case 'ArrowDown':
          e.preventDefault()
          const columnsPerRow = Math.floor(containerDimensions.width / 200) || 4
          setSelectedProductIndex(prev => {
            const newIndex = prev + columnsPerRow
            return newIndex <= maxIndex ? newIndex : prev
          })
          break
        case 'ArrowUp':
          e.preventDefault()
          const cols = Math.floor(containerDimensions.width / 200) || 4
          setSelectedProductIndex(prev => {
            const newIndex = prev - cols
            return newIndex >= 0 ? newIndex : prev
          })
          break
        case 'Enter':
          e.preventDefault()
          if (selectedProductIndex >= 0 && selectedProductIndex <= maxIndex) {
            addToCart(filteredItems[selectedProductIndex])
          }
          break
        case 'Escape':
          e.preventDefault()
          setSelectedProductIndex(-1)
          break
        case '/':
          e.preventDefault()
          // Focus search input
          const searchInput = document.querySelector('input[placeholder*="Search"]')
          if (searchInput) {
            searchInput.focus()
          }
          break
        case 'c':
          e.preventDefault()
          setIsCartCollapsed(!isCartCollapsed)
          break
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [filteredItems, selectedProductIndex, containerDimensions.width, addToCart, isCartCollapsed])

  return (
    <div className="h-screen bg-gray-50 dark:bg-gray-900 overflow-hidden">
      {/* Main Content - Full Width */}
      <div className="flex flex-col h-full">
        {/* Header */}
        <header className="bg-white dark:bg-gray-800 border-b">
          {/* Main Header Row */}
          <div className="px-6 py-3">
            <div className="flex items-center justify-between">
              {/* Left: Logo & Search */}
              <div className="flex items-center gap-4">
                <div>
                  <h1 className="text-lg font-bold gradient-text">TMR POS</h1>
                </div>
                
                <div className="relative enhanced-input">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground transition-colors" />
                  <Input
                    type="text"
                    placeholder="Search products... (Press / to focus)"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    className="pl-10 w-72 transition-all duration-200"
                  />
                  <div className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-muted-foreground bg-muted px-1.5 py-0.5 rounded">
                    /
                  </div>
                </div>
              </div>

              {/* Center: Customer Selection */}
              <div className="flex items-center gap-2">
                <label className="text-sm font-medium text-muted-foreground">Customer:</label>
                <select 
                  value={selectedCustomer || ""}
                  onChange={(e) => {
                    setSelectedCustomer(e.target.value || null);
                  }}
                  className="px-3 py-2 border rounded-lg bg-background min-w-[240px] text-sm focus:ring-2 focus:ring-primary/20 focus:border-primary"
                >
                  <option value="">Select Customer</option>
                  {customers.map(customer => (
                    <option key={customer.contact_id} value={customer.contact_id}>
                      {customer.contact_name}
                    </option>
                  ))}
                </select>
              </div>

              {/* Right: Status & Actions */}
              <div className="flex items-center gap-3">
                {/* Status Indicators */}
                <div className="flex items-center gap-2">
                  {/* Network Status */}
                  <div className="flex items-center gap-1">
                    {isOffline ? (
                      <Badge variant="outline" className="text-xs">
                        <WifiOff className="h-3 w-3 mr-1 text-orange-500" />
                        Offline
                      </Badge>
                    ) : (
                      <div className="flex items-center gap-1 text-xs text-emerald-600">
                        <Wifi className="h-3 w-3" />
                        <span>Online</span>
                        {authStatus.authenticated && (
                          <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse ml-1" />
                        )}
                      </div>
                    )}
                  </div>
                  
                  {pendingChanges > 0 && (
                    <Badge variant="warning" className="text-xs">
                      {pendingChanges} pending
                    </Badge>
                  )}
                </div>

                {/* Action Buttons */}
                <div className="flex items-center gap-1 border-l pl-3">
                  {!authStatus.authenticated && (
                    <Button size="sm" className="emerald-btn text-xs h-8" onClick={handleLogin}>
                      Connect Zoho
                    </Button>
                  )}
                  
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => setDark(!dark)}
                    className="interactive-scale h-8 w-8"
                    title="Toggle Theme"
                  >
                    {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
                  </Button>
                  
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => {
                      if (authStatus.authenticated) {
                        fetchItems()
                        fetchCustomers()
                      } else {
                        syncData()
                      }
                    }}
                    disabled={loading}
                    title={authStatus.authenticated ? "Refresh Data" : "Sync from Cache"}
                    className="interactive-scale h-8 w-8"
                  >
                    <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
                  </Button>

                  <Button
                    size="sm"
                    onClick={clearCart}
                    disabled={cart.length === 0}
                    className="enhanced-btn text-xs h-8 px-3"
                  >
                    <RefreshCw className="mr-1 h-3 w-3" />
                    New Sale
                  </Button>
                  
                  {/* Keyboard Shortcuts Help */}
                  <div className="relative group">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="interactive-scale h-8 w-8"
                      title="Keyboard Shortcuts"
                    >
                      <kbd className="text-xs bg-muted px-1 py-0.5 rounded">?</kbd>
                    </Button>
                    <div className="absolute top-full right-0 mt-2 w-56 bg-background border rounded-lg shadow-lg p-3 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-50">
                      <h4 className="font-semibold text-sm mb-2">Keyboard Shortcuts</h4>
                      <div className="space-y-1 text-xs">
                        <div className="flex justify-between">
                          <span>Search</span>
                          <kbd className="bg-muted px-1 rounded">/</kbd>
                        </div>
                        <div className="flex justify-between">
                          <span>Navigate</span>
                          <kbd className="bg-muted px-1 rounded">↑↓←→</kbd>
                        </div>
                        <div className="flex justify-between">
                          <span>Add to cart</span>
                          <kbd className="bg-muted px-1 rounded">Enter</kbd>
                        </div>
                        <div className="flex justify-between">
                          <span>Toggle cart</span>
                          <kbd className="bg-muted px-1 rounded">C</kbd>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Secondary Row: Tax Mode & Controls */}
          <div className="px-6 py-2 bg-gray-50 dark:bg-gray-800/50 border-t border-gray-100 dark:border-gray-700">
            <div className="flex items-center justify-between">
              {/* Left: Tax Mode Toggle */}
              <div className="flex items-center gap-3">
                <span className="text-sm font-medium text-muted-foreground">Tax:</span>
                <div className="flex items-center bg-white dark:bg-gray-800 border rounded-lg p-0.5">
                  <Button
                    size="sm"
                    onClick={() => setTaxMode("exclusive")}
                    className={`text-xs px-3 py-1 h-7 rounded-md transition-all ${
                      taxMode === "exclusive" 
                        ? 'bg-blue-600 text-white shadow-sm' 
                        : 'bg-transparent hover:bg-gray-100 dark:hover:bg-gray-700 text-muted-foreground'
                    }`}
                  >
                    {taxMode === "exclusive" && "✓ "}Exclusive
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => setTaxMode("inclusive")}
                    className={`text-xs px-3 py-1 h-7 rounded-md transition-all ${
                      taxMode === "inclusive" 
                        ? 'bg-green-600 text-white shadow-sm' 
                        : 'bg-transparent hover:bg-gray-100 dark:hover:bg-gray-700 text-muted-foreground'
                    }`}
                  >
                    {taxMode === "inclusive" && "✓ "}Inclusive
                  </Button>
                </div>
              </div>

              {/* Right: Sync Status */}
              <div className="flex items-center gap-2">
                {syncStatus && (
                  <Badge variant="outline" className="text-xs">
                    {syncStatus}
                  </Badge>
                )}
                {syncStatusLocal && (
                  <Badge variant="secondary" className="text-xs">
                    {syncStatusLocal}
                  </Badge>
                )}
                {items.length > 0 && (
                  <span className="text-xs text-muted-foreground">
                    {items.length} items loaded
                  </span>
                )}
              </div>
            </div>
          </div>

        
        </header>

        {/* Content Area */}
        <div className="flex-1 flex overflow-hidden">
          {/* Products Grid - Wider */}
          <div className="flex-1 overflow-y-auto p-6" ref={gridContainerRef}>
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

            {/* Products - Virtual Grid for Performance */}
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
            ) : (
              <VirtualProductGrid
                items={filteredItems}
                onAddToCart={addToCart}
                formatCurrency={formatCurrency}
                taxMode={taxMode}
                viewMode={viewMode}
                isMobile={isMobile}
                isLoading={loading}
                containerHeight={containerDimensions.height}
                containerWidth={containerDimensions.width}
                selectedIndex={selectedProductIndex}
                onProductSales={(item) => {
                  setSelectedProductForSales(item);
                  setShowProductSales(true);
                }}
                onLongPress={handleLongPressProduct}
              />
            )}
          </div>

          {/* Cart Sidebar - Collapsible */}
          <div className={cn(
            "bg-white dark:bg-gray-800 border-l flex flex-col transition-all duration-300 ease-in-out",
            isCartCollapsed ? "w-16" : "w-80"
          )}>
            <div className="p-4 border-b">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="relative">
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => setIsCartCollapsed(!isCartCollapsed)}
                      className="h-8 w-8 interactive-scale"
                      title={`${isCartCollapsed ? 'Expand' : 'Collapse'} cart (C)`}
                    >
                      <Menu className="h-4 w-4" />
                    </Button>
                    {!isCartCollapsed && (
                      <div className="absolute -top-1 -right-1 text-xs text-muted-foreground bg-muted px-1 py-0.5 rounded text-[10px]">
                        C
                      </div>
                    )}
                  </div>
                  {!isCartCollapsed && (
                    <h3 className="font-semibold flex items-center gap-2">
                      <ShoppingCart className="h-5 w-5" />
                      Cart ({subtotalQty})
                    </h3>
                  )}
                </div>
                {!isCartCollapsed && cart.length > 0 && (
                  <Button variant="ghost" size="sm" onClick={clearCart}>
                    Clear
                  </Button>
                )}
              </div>
              {isCartCollapsed && cart.length > 0 && (
                <div className="mt-2 text-center">
                  <Badge variant="default" className="text-xs">
                    {subtotalQty}
                  </Badge>
                </div>
              )}
            </div>

            {!isCartCollapsed && (
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
            )}

            {!isCartCollapsed && cart.length > 0 && (
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
                  className="w-full emerald-btn enhanced-btn glow-effect"
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
                        onClick={() => {
                          if (lastInvoice.pending) {
                            alert('Invoice is pending sync. PDF will be available once synced online.')
                          } else {
                            downloadInvoice(lastInvoice.invoice_id, lastInvoice.invoice_number)
                          }
                        }}
                        size="sm"
                        className="w-full text-xs bg-emerald-600 text-white hover:bg-emerald-700"
                        disabled={loading || lastInvoice.pending}
                      >
                        {lastInvoice.pending ? '⏳ Pending Sync' : '📥 Download PDF'}
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
    </div>
  )
}

export default App
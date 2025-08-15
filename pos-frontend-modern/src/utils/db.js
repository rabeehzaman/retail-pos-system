import { openDB } from 'idb'

const DB_NAME = 'TMR_POS_DB'
const DB_VERSION = 1

// Initialize IndexedDB
export const initDB = async () => {
  return openDB(DB_NAME, DB_VERSION, {
    upgrade(db, oldVersion, newVersion, transaction) {
      // Products store
      if (!db.objectStoreNames.contains('products')) {
        const productStore = db.createObjectStore('products', { keyPath: 'id' })
        productStore.createIndex('name', 'name')
        productStore.createIndex('sku', 'sku')
        productStore.createIndex('category', 'category_name')
      }

      // Customers store
      if (!db.objectStoreNames.contains('customers')) {
        const customerStore = db.createObjectStore('customers', { keyPath: 'id' })
        customerStore.createIndex('name', 'display_name')
        customerStore.createIndex('email', 'email')
      }

      // Auth store for tokens
      if (!db.objectStoreNames.contains('auth')) {
        db.createObjectStore('auth', { keyPath: 'key' })
      }

      // Pending transactions store for offline mode
      if (!db.objectStoreNames.contains('pendingTransactions')) {
        const transactionStore = db.createObjectStore('pendingTransactions', { 
          keyPath: 'localId', 
          autoIncrement: true 
        })
        transactionStore.createIndex('timestamp', 'timestamp')
      }

      // Settings store for user preferences
      if (!db.objectStoreNames.contains('settings')) {
        db.createObjectStore('settings', { keyPath: 'key' })
      }

      // Cart store for persistent cart
      if (!db.objectStoreNames.contains('cart')) {
        db.createObjectStore('cart', { keyPath: 'id' })
      }
    }
  })
}

// Products operations
export const saveProducts = async (products) => {
  const db = await initDB()
  const tx = db.transaction('products', 'readwrite')
  const store = tx.objectStore('products')
  
  // Clear existing products and add new ones
  await store.clear()
  for (const product of products) {
    await store.put(product)
  }
  
  await tx.complete
  return products
}

export const getProducts = async () => {
  const db = await initDB()
  return db.getAll('products')
}

export const searchProducts = async (searchTerm) => {
  const db = await initDB()
  const products = await db.getAll('products')
  
  const term = searchTerm.toLowerCase()
  return products.filter(p => 
    p.name?.toLowerCase().includes(term) || 
    p.sku?.toLowerCase().includes(term)
  )
}

// Customers operations
export const saveCustomers = async (customers) => {
  const db = await initDB()
  const tx = db.transaction('customers', 'readwrite')
  const store = tx.objectStore('customers')
  
  await store.clear()
  for (const customer of customers) {
    await store.put(customer)
  }
  
  await tx.complete
  return customers
}

export const getCustomers = async () => {
  const db = await initDB()
  return db.getAll('customers')
}

// Auth operations
export const saveAuthToken = async (token, refreshToken) => {
  const db = await initDB()
  const tx = db.transaction('auth', 'readwrite')
  const store = tx.objectStore('auth')
  
  await store.put({ key: 'accessToken', value: token, timestamp: Date.now() })
  if (refreshToken) {
    await store.put({ key: 'refreshToken', value: refreshToken, timestamp: Date.now() })
  }
  
  await tx.complete
}

export const getAuthTokens = async () => {
  const db = await initDB()
  const accessToken = await db.get('auth', 'accessToken')
  const refreshToken = await db.get('auth', 'refreshToken')
  
  return {
    accessToken: accessToken?.value,
    refreshToken: refreshToken?.value,
    timestamp: accessToken?.timestamp
  }
}

export const clearAuthTokens = async () => {
  const db = await initDB()
  const tx = db.transaction('auth', 'readwrite')
  await tx.objectStore('auth').clear()
  await tx.complete
}

// Settings operations
export const saveSetting = async (key, value) => {
  const db = await initDB()
  await db.put('settings', { key, value, timestamp: Date.now() })
}

export const getSetting = async (key) => {
  const db = await initDB()
  const setting = await db.get('settings', key)
  return setting?.value
}

export const getAllSettings = async () => {
  const db = await initDB()
  const settings = await db.getAll('settings')
  const result = {}
  settings.forEach(s => {
    result[s.key] = s.value
  })
  return result
}

// Cart operations
export const saveCart = async (cartItems) => {
  const db = await initDB()
  const tx = db.transaction('cart', 'readwrite')
  const store = tx.objectStore('cart')
  
  await store.clear()
  for (const item of cartItems) {
    await store.put(item)
  }
  
  await tx.complete
  return cartItems
}

export const getCart = async () => {
  const db = await initDB()
  return db.getAll('cart')
}

export const clearCart = async () => {
  const db = await initDB()
  const tx = db.transaction('cart', 'readwrite')
  await tx.objectStore('cart').clear()
  await tx.complete
}

// Pending transactions for offline mode
export const savePendingTransaction = async (transaction) => {
  const db = await initDB()
  const tx = db.transaction('pendingTransactions', 'readwrite')
  const store = tx.objectStore('pendingTransactions')
  
  const id = await store.add({
    ...transaction,
    timestamp: Date.now(),
    synced: false
  })
  
  await tx.complete
  return id
}

export const getPendingTransactions = async () => {
  const db = await initDB()
  return db.getAll('pendingTransactions')
}

export const markTransactionSynced = async (localId) => {
  const db = await initDB()
  const tx = db.transaction('pendingTransactions', 'readwrite')
  const store = tx.objectStore('pendingTransactions')
  
  const transaction = await store.get(localId)
  if (transaction) {
    transaction.synced = true
    transaction.syncedAt = Date.now()
    await store.put(transaction)
  }
  
  await tx.complete
}

export const removeSyncedTransactions = async () => {
  const db = await initDB()
  const tx = db.transaction('pendingTransactions', 'readwrite')
  const store = tx.objectStore('pendingTransactions')
  
  const all = await store.getAll()
  for (const transaction of all) {
    if (transaction.synced) {
      await store.delete(transaction.localId)
    }
  }
  
  await tx.complete
}

// Clear all data (for logout)
export const clearAllData = async () => {
  const db = await initDB()
  
  const stores = ['products', 'customers', 'auth', 'pendingTransactions', 'cart']
  
  for (const storeName of stores) {
    const tx = db.transaction(storeName, 'readwrite')
    await tx.objectStore(storeName).clear()
    await tx.complete
  }
}
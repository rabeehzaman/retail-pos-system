import { useState, useEffect, useCallback } from 'react'
import axios from 'axios'
import * as db from '../utils/db'
import * as localStorage from '../utils/localStorage'
import { isOnline, onOnline, onOffline, shouldSync, retryWithBackoff } from '../utils/offline'

export function useOfflineSync(backendUrl) {
  const [isOffline, setIsOffline] = useState(!isOnline())
  const [syncStatus, setSyncStatus] = useState('idle')
  const [lastSyncTime, setLastSyncTime] = useState(null)
  const [pendingChanges, setPendingChanges] = useState(0)

  // Monitor online/offline status
  useEffect(() => {
    const unsubscribeOnline = onOnline(() => {
      setIsOffline(false)
      syncData() // Sync when coming back online
    })

    const unsubscribeOffline = onOffline(() => {
      setIsOffline(true)
    })

    return () => {
      unsubscribeOnline()
      unsubscribeOffline()
    }
  }, [])

  // Load last sync time on mount
  useEffect(() => {
    const time = localStorage.getLastSyncTime()
    setLastSyncTime(time)
  }, [])

  // Check pending transactions
  useEffect(() => {
    const checkPending = async () => {
      const pending = await db.getPendingTransactions()
      setPendingChanges(pending.filter(t => !t.synced).length)
    }
    checkPending()
    const interval = setInterval(checkPending, 10000) // Check every 10 seconds
    return () => clearInterval(interval)
  }, [])

  // Sync products with IndexedDB
  const syncProducts = useCallback(async (forceRefresh = false) => {
    try {
      // Check if we have cached data
      const cachedProducts = await db.getProducts()
      
      // Use cached data if offline or if data is fresh (less than 1 hour old)
      if (!forceRefresh && (isOffline || (cachedProducts.length > 0 && 
          lastSyncTime && Date.now() - lastSyncTime < 3600000))) {
        return cachedProducts
      }

      // Fetch fresh data if online
      if (isOnline() && shouldSync()) {
        setSyncStatus('syncing')
        
        const response = await retryWithBackoff(async () => {
          return await axios.get(`${backendUrl}/api/items`)
        })

        if (response.data.items) {
          await db.saveProducts(response.data.items)
          localStorage.saveLastSyncTime()
          setLastSyncTime(Date.now())
          setSyncStatus('synced')
          return response.data.items
        }
      }

      return cachedProducts
    } catch (error) {
      console.error('Product sync failed:', error)
      setSyncStatus('error')
      
      // Fall back to cached data
      const cachedProducts = await db.getProducts()
      return cachedProducts
    }
  }, [backendUrl, isOffline, lastSyncTime])

  // Sync customers with IndexedDB
  const syncCustomers = useCallback(async (forceRefresh = false) => {
    try {
      const cachedCustomers = await db.getCustomers()
      
      // Always force refresh if no customers are cached
      if (cachedCustomers.length === 0) {
        forceRefresh = true
      }
      
      if (!forceRefresh && (isOffline || (cachedCustomers.length > 0 && 
          lastSyncTime && Date.now() - lastSyncTime < 3600000))) {
        return cachedCustomers
      }

      if (isOnline() && shouldSync()) {
        setSyncStatus('syncing')
        const response = await retryWithBackoff(async () => {
          return await axios.get(`${backendUrl}/api/customers`)
        }, 3, 1000) // 3 retries with 1 second initial delay

        if (response.data.customers) {
          await db.saveCustomers(response.data.customers)
          setSyncStatus('synced')
          return response.data.customers
        }
      }

      return cachedCustomers || []
    } catch (error) {
      console.error('Customer sync failed:', error)
      const cachedCustomers = await db.getCustomers()
      return cachedCustomers
    }
  }, [backendUrl, isOffline, lastSyncTime])

  // Save transaction (works offline)
  const saveTransaction = useCallback(async (transaction) => {
    try {
      if (isOnline()) {
        // Try to save online first
        const response = await axios.post(`${backendUrl}/api/invoices`, transaction)
        return response.data
      } else {
        // Save to IndexedDB for later sync
        const localId = await db.savePendingTransaction(transaction)
        setPendingChanges(prev => prev + 1)
        return { localId, pending: true }
      }
    } catch (error) {
      console.error('Failed to save transaction:', error)
      
      // Save offline if online save failed
      const localId = await db.savePendingTransaction(transaction)
      setPendingChanges(prev => prev + 1)
      return { localId, pending: true }
    }
  }, [backendUrl])

  // Sync pending transactions
  const syncPendingTransactions = useCallback(async () => {
    if (!isOnline() || !shouldSync()) return

    try {
      const pending = await db.getPendingTransactions()
      const unsynced = pending.filter(t => !t.synced)

      for (const transaction of unsynced) {
        try {
          await axios.post(`${backendUrl}/api/invoices`, transaction)
          await db.markTransactionSynced(transaction.localId)
        } catch (error) {
          console.error('Failed to sync transaction:', transaction.localId, error)
        }
      }

      // Clean up synced transactions
      await db.removeSyncedTransactions()
      setPendingChanges(0)
    } catch (error) {
      console.error('Failed to sync pending transactions:', error)
    }
  }, [backendUrl])

  // Main sync function
  const syncData = useCallback(async () => {
    if (!isOnline() || !shouldSync()) return

    setSyncStatus('syncing')
    
    try {
      await Promise.all([
        syncProducts(true),
        syncCustomers(true),
        syncPendingTransactions()
      ])
      
      setSyncStatus('synced')
      localStorage.saveLastSyncTime()
      setLastSyncTime(Date.now())
    } catch (error) {
      console.error('Sync failed:', error)
      setSyncStatus('error')
    }
  }, [syncProducts, syncCustomers, syncPendingTransactions])

  // Auto-sync every 5 minutes when online
  useEffect(() => {
    if (!isOffline) {
      const interval = setInterval(() => {
        if (shouldSync()) {
          syncData()
        }
      }, 300000) // 5 minutes

      return () => clearInterval(interval)
    }
  }, [isOffline, syncData])

  return {
    isOffline,
    syncStatus,
    lastSyncTime,
    pendingChanges,
    syncProducts,
    syncCustomers,
    saveTransaction,
    syncData,
    syncPendingTransactions
  }
}
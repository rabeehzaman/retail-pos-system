import { Workbox } from 'workbox-window'

// Network status detection
export const isOnline = () => navigator.onLine

// Create event listeners for online/offline status
export const onOnline = (callback) => {
  window.addEventListener('online', callback)
  return () => window.removeEventListener('online', callback)
}

export const onOffline = (callback) => {
  window.addEventListener('offline', callback)
  return () => window.removeEventListener('offline', callback)
}

// Service Worker registration and update handling
export const registerServiceWorker = async () => {
  if ('serviceWorker' in navigator && import.meta.env.PROD) {
    const wb = new Workbox('/sw.js')

    // Add event listeners
    wb.addEventListener('installed', (event) => {
      if (!event.isUpdate) {
        console.log('Service Worker installed for the first time')
      }
    })

    wb.addEventListener('waiting', () => {
      // New service worker is waiting to activate
      // You can show a prompt to the user to reload
      if (confirm('New version available! Click OK to update.')) {
        wb.addEventListener('controlling', () => {
          window.location.reload()
        })
        wb.messageSkipWaiting()
      }
    })

    wb.addEventListener('activated', (event) => {
      if (event.isUpdate) {
        console.log('Service Worker updated')
      }
    })

    try {
      const registration = await wb.register()
      console.log('Service Worker registered:', registration)
      return wb
    } catch (error) {
      console.error('Service Worker registration failed:', error)
    }
  }
}

// Background sync for offline transactions
export const registerBackgroundSync = async (tag = 'sync-transactions') => {
  if ('serviceWorker' in navigator && 'sync' in self.registration) {
    try {
      const registration = await navigator.serviceWorker.ready
      await registration.sync.register(tag)
      console.log('Background sync registered:', tag)
    } catch (error) {
      console.error('Background sync registration failed:', error)
    }
  }
}

// Check if we have cached data
export const hasCachedData = async () => {
  if ('caches' in window) {
    try {
      const cacheNames = await caches.keys()
      return cacheNames.length > 0
    } catch (error) {
      console.error('Failed to check cache:', error)
      return false
    }
  }
  return false
}

// Clear all caches (for debugging/reset)
export const clearAllCaches = async () => {
  if ('caches' in window) {
    try {
      const cacheNames = await caches.keys()
      await Promise.all(
        cacheNames.map(cacheName => caches.delete(cacheName))
      )
      console.log('All caches cleared')
    } catch (error) {
      console.error('Failed to clear caches:', error)
    }
  }
}

// Prefetch critical resources
export const prefetchResources = async (urls = []) => {
  if ('caches' in window) {
    try {
      const cache = await caches.open('prefetch-cache')
      await cache.addAll(urls)
      console.log('Resources prefetched:', urls)
    } catch (error) {
      console.error('Failed to prefetch resources:', error)
    }
  }
}

// Network quality detection
export const getNetworkQuality = () => {
  const connection = navigator.connection || 
                     navigator.mozConnection || 
                     navigator.webkitConnection

  if (connection) {
    return {
      effectiveType: connection.effectiveType, // 'slow-2g', '2g', '3g', '4g'
      downlink: connection.downlink, // Mbps
      rtt: connection.rtt, // Round-trip time in ms
      saveData: connection.saveData // Data saver enabled
    }
  }

  return {
    effectiveType: 'unknown',
    downlink: null,
    rtt: null,
    saveData: false
  }
}

// Smart sync based on network quality
export const shouldSync = () => {
  const quality = getNetworkQuality()
  
  // Don't sync on slow connections or when data saver is on
  if (quality.saveData || quality.effectiveType === 'slow-2g') {
    return false
  }
  
  // Always sync on good connections
  if (quality.effectiveType === '4g') {
    return true
  }
  
  // For 2g/3g, sync only if online
  return isOnline()
}

// Retry failed requests with exponential backoff
export const retryWithBackoff = async (
  fn, 
  maxRetries = 3, 
  baseDelay = 1000
) => {
  let lastError

  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn()
    } catch (error) {
      lastError = error
      
      if (i < maxRetries - 1) {
        const delay = baseDelay * Math.pow(2, i)
        await new Promise(resolve => setTimeout(resolve, delay))
      }
    }
  }

  throw lastError
}
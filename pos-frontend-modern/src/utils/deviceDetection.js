// Device and browser detection utilities

export const isIOS = () => {
  return /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream
}

export const isSafari = () => {
  const ua = navigator.userAgent.toLowerCase()
  return ua.indexOf('safari') > -1 && ua.indexOf('chrome') === -1
}

export const isIOSSafari = () => {
  return isIOS() && isSafari()
}

export const isMobileDevice = () => {
  return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent)
}

export const getDeviceType = () => {
  const ua = navigator.userAgent
  if (/iPad/.test(ua)) return 'ipad'
  if (/iPhone/.test(ua)) return 'iphone'
  if (/Android/.test(ua)) return 'android'
  if (isMobileDevice()) return 'mobile'
  return 'desktop'
}

// Check if device has limited memory (useful for optimization)
export const hasLimitedMemory = () => {
  // Check if device memory API is available
  if ('deviceMemory' in navigator) {
    return navigator.deviceMemory < 4 // Less than 4GB RAM
  }
  
  // Fallback: assume mobile devices have limited memory
  return isMobileDevice()
}

// Check if device can handle large lists efficiently
export const canHandleLargeLists = () => {
  // iOS Safari has issues with virtual scrolling for large lists
  if (isIOSSafari()) {
    return false
  }
  
  // Check device memory if available
  if (hasLimitedMemory()) {
    return false
  }
  
  return true
}

// Get optimal batch size for data loading
export const getOptimalBatchSize = () => {
  if (isIOSSafari()) return 50 // Small batches for iOS Safari
  if (hasLimitedMemory()) return 100
  return 200 // Default batch size
}
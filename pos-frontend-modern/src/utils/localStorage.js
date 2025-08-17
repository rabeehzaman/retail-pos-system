// LocalStorage utility for user preferences and settings

const STORAGE_KEYS = {
  THEME: 'tmr_pos_theme',
  TAX_MODE: 'tmr_pos_tax_mode',
  VIEW_MODE: 'tmr_pos_view_mode',
  LAST_CUSTOMER: 'tmr_pos_last_customer',
  LAST_SYNC: 'tmr_pos_last_sync',
  AUTH_STATUS: 'tmr_pos_auth_status',
  USER_PREFS: 'tmr_pos_user_prefs',
  SELECTED_BRANCH: 'tmr_pos_selected_branch'
}

// Theme preferences
export const saveTheme = (isDark) => {
  try {
    localStorage.setItem(STORAGE_KEYS.THEME, JSON.stringify(isDark))
  } catch (e) {
    console.error('Failed to save theme:', e)
  }
}

export const getTheme = () => {
  try {
    const theme = localStorage.getItem(STORAGE_KEYS.THEME)
    return theme ? JSON.parse(theme) : false
  } catch (e) {
    console.error('Failed to get theme:', e)
    return false
  }
}

// Tax mode
export const saveTaxMode = (mode) => {
  try {
    localStorage.setItem(STORAGE_KEYS.TAX_MODE, mode)
  } catch (e) {
    console.error('Failed to save tax mode:', e)
  }
}

export const getTaxMode = () => {
  try {
    return localStorage.getItem(STORAGE_KEYS.TAX_MODE) || 'exclusive'
  } catch (e) {
    console.error('Failed to get tax mode:', e)
    return 'exclusive'
  }
}

// View mode
export const saveViewMode = (mode) => {
  try {
    localStorage.setItem(STORAGE_KEYS.VIEW_MODE, mode)
  } catch (e) {
    console.error('Failed to save view mode:', e)
  }
}

export const getViewMode = () => {
  try {
    return localStorage.getItem(STORAGE_KEYS.VIEW_MODE) || 'grid'
  } catch (e) {
    console.error('Failed to get view mode:', e)
    return 'grid'
  }
}

// Last selected customer
export const saveLastCustomer = (customer) => {
  try {
    localStorage.setItem(STORAGE_KEYS.LAST_CUSTOMER, JSON.stringify(customer))
  } catch (e) {
    console.error('Failed to save last customer:', e)
  }
}

export const getLastCustomer = () => {
  try {
    const customer = localStorage.getItem(STORAGE_KEYS.LAST_CUSTOMER)
    return customer ? JSON.parse(customer) : null
  } catch (e) {
    console.error('Failed to get last customer:', e)
    return null
  }
}

// Last sync time
export const saveLastSyncTime = (timestamp = Date.now()) => {
  try {
    localStorage.setItem(STORAGE_KEYS.LAST_SYNC, timestamp.toString())
  } catch (e) {
    console.error('Failed to save last sync time:', e)
  }
}

export const getLastSyncTime = () => {
  try {
    const time = localStorage.getItem(STORAGE_KEYS.LAST_SYNC)
    return time ? parseInt(time) : null
  } catch (e) {
    console.error('Failed to get last sync time:', e)
    return null
  }
}

// Auth status
export const saveAuthStatus = (status) => {
  try {
    localStorage.setItem(STORAGE_KEYS.AUTH_STATUS, JSON.stringify(status))
  } catch (e) {
    console.error('Failed to save auth status:', e)
  }
}

export const getAuthStatus = () => {
  try {
    const status = localStorage.getItem(STORAGE_KEYS.AUTH_STATUS)
    return status ? JSON.parse(status) : { authenticated: false }
  } catch (e) {
    console.error('Failed to get auth status:', e)
    return { authenticated: false }
  }
}

// Selected branch
export const saveSelectedBranch = (branch) => {
  try {
    localStorage.setItem(STORAGE_KEYS.SELECTED_BRANCH, JSON.stringify(branch))
  } catch (e) {
    console.error('Failed to save selected branch:', e)
  }
}

export const getSelectedBranch = () => {
  try {
    const branch = localStorage.getItem(STORAGE_KEYS.SELECTED_BRANCH)
    return branch ? JSON.parse(branch) : null
  } catch (e) {
    console.error('Failed to get selected branch:', e)
    return null
  }
}

// User preferences bundle
export const saveUserPreferences = (prefs) => {
  try {
    localStorage.setItem(STORAGE_KEYS.USER_PREFS, JSON.stringify(prefs))
  } catch (e) {
    console.error('Failed to save user preferences:', e)
  }
}

export const getUserPreferences = () => {
  try {
    const prefs = localStorage.getItem(STORAGE_KEYS.USER_PREFS)
    return prefs ? JSON.parse(prefs) : {}
  } catch (e) {
    console.error('Failed to get user preferences:', e)
    return {}
  }
}

// Clear all localStorage
export const clearAllStorage = () => {
  try {
    Object.values(STORAGE_KEYS).forEach(key => {
      localStorage.removeItem(key)
    })
  } catch (e) {
    console.error('Failed to clear storage:', e)
  }
}

// Check if localStorage is available
export const isLocalStorageAvailable = () => {
  try {
    const test = '__localStorage_test__'
    localStorage.setItem(test, test)
    localStorage.removeItem(test)
    return true
  } catch (e) {
    return false
  }
}
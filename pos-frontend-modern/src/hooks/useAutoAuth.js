import { useState, useEffect, useCallback } from 'react'
import axios from 'axios'
import * as db from '../utils/db'
import * as localStorage from '../utils/localStorage'
import { isOnline } from '../utils/offline'

export function useAutoAuth(backendUrl) {
  const [authStatus, setAuthStatus] = useState({ 
    authenticated: false, 
    loading: true,
    user: null 
  })
  const [authError, setAuthError] = useState(null)

  // Check stored auth on mount
  useEffect(() => {
    checkStoredAuth()
  }, [])

  // Check if we have valid stored authentication
  const checkStoredAuth = useCallback(async () => {
    try {
      // First check localStorage for quick status
      const storedStatus = localStorage.getAuthStatus()
      
      if (storedStatus.authenticated) {
        // Check IndexedDB for tokens
        const tokens = await db.getAuthTokens()
        
        if (tokens.accessToken) {
          // Check if token is still valid (less than 24 hours old)
          const tokenAge = Date.now() - (tokens.timestamp || 0)
          const isTokenFresh = tokenAge < 24 * 60 * 60 * 1000 // 24 hours
          
          if (isTokenFresh) {
            // Set auth header for all requests
            axios.defaults.headers.common['Authorization'] = `Bearer ${tokens.accessToken}`
            
            // Verify with backend if online
            if (isOnline()) {
              try {
                const response = await axios.get(`${backendUrl}/auth/status`)
                
                if (response.data.authenticated) {
                  setAuthStatus({
                    authenticated: true,
                    loading: false,
                    user: response.data.user
                  })
                  return true
                }
              } catch (error) {
                console.error('Token validation failed:', error)
                // Token might be expired, try to refresh
                if (tokens.refreshToken) {
                  return await refreshAuth(tokens.refreshToken)
                }
              }
            } else {
              // Offline - trust the stored token
              setAuthStatus({
                authenticated: true,
                loading: false,
                user: storedStatus.user
              })
              return true
            }
          } else if (tokens.refreshToken) {
            // Token is old, try to refresh
            return await refreshAuth(tokens.refreshToken)
          }
        }
      }
      
      // No valid auth found
      setAuthStatus({ authenticated: false, loading: false, user: null })
      return false
    } catch (error) {
      console.error('Auto-auth check failed:', error)
      setAuthError(error.message)
      setAuthStatus({ authenticated: false, loading: false, user: null })
      return false
    }
  }, [backendUrl])

  // Refresh authentication using refresh token
  const refreshAuth = useCallback(async (refreshToken) => {
    if (!isOnline()) {
      console.log('Cannot refresh auth while offline')
      return false
    }

    try {
      const response = await axios.post(`${backendUrl}/auth/refresh`, {
        refreshToken
      })

      if (response.data.accessToken) {
        // Save new tokens
        await db.saveAuthToken(response.data.accessToken, response.data.refreshToken)
        
        // Update axios default header
        axios.defaults.headers.common['Authorization'] = `Bearer ${response.data.accessToken}`
        
        // Update auth status
        const newStatus = {
          authenticated: true,
          loading: false,
          user: response.data.user
        }
        
        setAuthStatus(newStatus)
        localStorage.saveAuthStatus(newStatus)
        
        return true
      }
    } catch (error) {
      console.error('Token refresh failed:', error)
      setAuthError('Session expired. Please login again.')
      
      // Clear invalid tokens
      await clearAuth()
      return false
    }
  }, [backendUrl])

  // Manual login
  const login = useCallback(async () => {
    try {
      setAuthStatus(prev => ({ ...prev, loading: true }))
      
      // Open OAuth window
      const authWindow = window.open(
        `${backendUrl}/auth/login`, 
        '_blank', 
        'width=600,height=700'
      )
      
      // Poll for auth completion
      return new Promise((resolve) => {
        const checkAuth = setInterval(async () => {
          try {
            const response = await axios.get(`${backendUrl}/auth/status`)
            
            if (response.data.authenticated) {
              clearInterval(checkAuth)
              
              // Save tokens if provided
              if (response.data.accessToken) {
                await db.saveAuthToken(
                  response.data.accessToken, 
                  response.data.refreshToken
                )
                
                axios.defaults.headers.common['Authorization'] = 
                  `Bearer ${response.data.accessToken}`
              }
              
              // Update status
              const newStatus = {
                authenticated: true,
                loading: false,
                user: response.data.user
              }
              
              setAuthStatus(newStatus)
              localStorage.saveAuthStatus(newStatus)
              
              if (authWindow && !authWindow.closed) {
                authWindow.close()
              }
              
              resolve(true)
            }
          } catch (error) {
            console.error('Auth check failed:', error)
          }
        }, 2000)
        
        // Timeout after 60 seconds
        setTimeout(() => {
          clearInterval(checkAuth)
          setAuthStatus(prev => ({ ...prev, loading: false }))
          resolve(false)
        }, 60000)
      })
    } catch (error) {
      console.error('Login failed:', error)
      setAuthError(error.message)
      setAuthStatus(prev => ({ ...prev, loading: false }))
      return false
    }
  }, [backendUrl])

  // Logout
  const logout = useCallback(async () => {
    try {
      // Clear backend session if online
      if (isOnline()) {
        try {
          await axios.post(`${backendUrl}/auth/logout`)
        } catch (error) {
          console.error('Backend logout failed:', error)
        }
      }
      
      // Clear local auth
      await clearAuth()
      
      return true
    } catch (error) {
      console.error('Logout failed:', error)
      return false
    }
  }, [backendUrl])

  // Clear all auth data
  const clearAuth = useCallback(async () => {
    // Clear tokens from IndexedDB
    await db.clearAuthTokens()
    
    // Clear auth status from localStorage
    localStorage.saveAuthStatus({ authenticated: false })
    
    // Remove auth header
    delete axios.defaults.headers.common['Authorization']
    
    // Update state
    setAuthStatus({ authenticated: false, loading: false, user: null })
    setAuthError(null)
  }, [])

  // Auto-refresh token before expiry
  useEffect(() => {
    if (authStatus.authenticated) {
      // Refresh token every 20 hours
      const refreshInterval = setInterval(async () => {
        const tokens = await db.getAuthTokens()
        if (tokens.refreshToken) {
          refreshAuth(tokens.refreshToken)
        }
      }, 20 * 60 * 60 * 1000) // 20 hours
      
      return () => clearInterval(refreshInterval)
    }
  }, [authStatus.authenticated, refreshAuth])

  return {
    authStatus,
    authError,
    login,
    logout,
    refreshAuth,
    checkStoredAuth
  }
}
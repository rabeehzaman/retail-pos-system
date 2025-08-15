import React, { useState, useEffect } from 'react'
import App from './App'
import AppMobile from './AppMobile'

function AppWrapper() {
  const [isMobile, setIsMobile] = useState(false)

  useEffect(() => {
    const checkDevice = () => {
      // Check for mobile based on viewport width and touch capability
      const mobileWidth = window.innerWidth < 768
      const hasTouch = 'ontouchstart' in window || navigator.maxTouchPoints > 0
      setIsMobile(mobileWidth || (hasTouch && window.innerWidth < 1024))
    }

    checkDevice()
    window.addEventListener('resize', checkDevice)
    
    return () => window.removeEventListener('resize', checkDevice)
  }, [])

  return isMobile ? <AppMobile /> : <App />
}

export default AppWrapper
import React, { useEffect, useState } from 'react'
import { X, CheckCircle, AlertCircle, AlertTriangle, Info } from 'lucide-react'
import { cn } from '../lib/utils'

const Toast = ({ message, type = 'info', duration = 5000, onClose, action }) => {
  const [isVisible, setIsVisible] = useState(true)
  const [isLeaving, setIsLeaving] = useState(false)

  useEffect(() => {
    if (duration > 0) {
      const timer = setTimeout(() => {
        handleClose()
      }, duration)

      return () => clearTimeout(timer)
    }
  }, [duration])

  const handleClose = () => {
    setIsLeaving(true)
    setTimeout(() => {
      setIsVisible(false)
      onClose?.()
    }, 300) // Match animation duration
  }

  const getIcon = () => {
    switch (type) {
      case 'success':
        return <CheckCircle className="h-5 w-5 text-emerald-500" />
      case 'error':
        return <AlertCircle className="h-5 w-5 text-red-500" />
      case 'warning':
        return <AlertTriangle className="h-5 w-5 text-amber-500" />
      default:
        return <Info className="h-5 w-5 text-blue-500" />
    }
  }

  const getBackgroundColor = () => {
    switch (type) {
      case 'success':
        return 'bg-emerald-50 border-emerald-200 dark:bg-emerald-950 dark:border-emerald-800'
      case 'error':
        return 'bg-red-50 border-red-200 dark:bg-red-950 dark:border-red-800'
      case 'warning':
        return 'bg-amber-50 border-amber-200 dark:bg-amber-950 dark:border-amber-800'
      default:
        return 'bg-blue-50 border-blue-200 dark:bg-blue-950 dark:border-blue-800'
    }
  }

  if (!isVisible) return null

  return (
    <div
      className={cn(
        "fixed top-4 left-4 right-4 z-50 mx-auto max-w-sm",
        "transform transition-all duration-300 ease-in-out",
        isLeaving ? "translate-y-[-100%] opacity-0" : "translate-y-0 opacity-100"
      )}
    >
      <div
        className={cn(
          "rounded-lg border shadow-lg p-4",
          getBackgroundColor()
        )}
      >
        <div className="flex items-start gap-3">
          <div className="flex-shrink-0 mt-0.5">
            {getIcon()}
          </div>
          
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
              {message}
            </p>
            
            {action && (
              <div className="mt-2">
                {action}
              </div>
            )}
          </div>
          
          <button
            onClick={handleClose}
            className="flex-shrink-0 ml-2 p-1 rounded-md hover:bg-black/5 dark:hover:bg-white/5 transition-colors"
          >
            <X className="h-4 w-4 text-gray-400" />
          </button>
        </div>
      </div>
    </div>
  )
}

export default Toast
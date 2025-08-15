import React, { useState } from 'react'
import { X, Plus, Minus, Trash2, ShoppingCart, CreditCard } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { cn } from '../lib/utils'

export function MobileCart({ 
  cart, 
  onUpdateQuantity, 
  onRemoveItem,
  onCheckout,
  formatCurrency,
  taxMode,
  selectedCustomer,
  onClose,
  isFullScreen = false
}) {
  const [swipedItem, setSwipedItem] = useState(null)

  const calculateSubtotal = () => {
    return cart.reduce((sum, item) => sum + (item.price * item.quantity), 0)
  }

  const calculateTax = (subtotal) => {
    return taxMode === "exclusive" ? subtotal * 0.15 : 0
  }

  const calculateTotal = () => {
    const subtotal = calculateSubtotal()
    const tax = calculateTax(subtotal)
    return taxMode === "inclusive" ? subtotal : subtotal + tax
  }

  const handleSwipeStart = (itemId, startX) => {
    const element = document.getElementById(`cart-item-${itemId}`)
    if (!element) return

    let currentX = startX
    let diff = 0

    const handleMove = (e) => {
      const touch = e.touches ? e.touches[0] : e
      diff = touch.clientX - currentX
      
      if (diff < -20) {
        setSwipedItem(itemId)
        element.style.transform = `translateX(${Math.max(diff, -80)}px)`
      } else if (diff > 20 && swipedItem === itemId) {
        setSwipedItem(null)
        element.style.transform = 'translateX(0)'
      }
    }

    const handleEnd = () => {
      if (diff < -50) {
        setSwipedItem(itemId)
        element.style.transform = 'translateX(-80px)'
      } else {
        setSwipedItem(null)
        element.style.transform = 'translateX(0)'
      }
      
      document.removeEventListener('touchmove', handleMove)
      document.removeEventListener('touchend', handleEnd)
      document.removeEventListener('mousemove', handleMove)
      document.removeEventListener('mouseup', handleEnd)
    }

    document.addEventListener('touchmove', handleMove)
    document.addEventListener('touchend', handleEnd)
    document.addEventListener('mousemove', handleMove)
    document.addEventListener('mouseup', handleEnd)
  }

  if (cart.length === 0) {
    return (
      <div className={cn(
        "flex flex-col items-center justify-center",
        isFullScreen ? "h-full" : "py-12"
      )}>
        <ShoppingCart className="h-16 w-16 text-muted-foreground mb-4" />
        <p className="text-lg font-medium mb-2">Your cart is empty</p>
        <p className="text-sm text-muted-foreground mb-4">Add items to get started</p>
        {isFullScreen && (
          <Button onClick={onClose} variant="default">
            Start Shopping
          </Button>
        )}
      </div>
    )
  }

  return (
    <div className={cn(
      "flex flex-col",
      isFullScreen ? "h-full" : ""
    )}>
      {isFullScreen && (
        <div className="flex items-center justify-between p-4 border-b">
          <h2 className="text-lg font-semibold">Shopping Cart</h2>
          <Button
            variant="ghost"
            size="icon"
            onClick={onClose}
          >
            <X className="h-5 w-5" />
          </Button>
        </div>
      )}

      <div className="flex-1 overflow-y-auto">
        <div className="p-4 space-y-3">
          {cart.map((item) => (
            <div
              key={item.id}
              className="relative overflow-hidden"
            >
              <div
                id={`cart-item-${item.id}`}
                className="bg-card border rounded-lg p-4 transition-transform duration-200"
                onTouchStart={(e) => handleSwipeStart(item.id, e.touches[0].clientX)}
                onMouseDown={(e) => handleSwipeStart(item.id, e.clientX)}
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex-1">
                    <h4 className="font-medium text-sm line-clamp-2">{item.name}</h4>
                    <p className="text-xs text-muted-foreground mt-1">
                      {formatCurrency(item.price)} × {item.quantity}
                    </p>
                  </div>
                  <div className="text-right ml-3">
                    <p className="font-semibold text-primary">
                      {formatCurrency(item.price * item.quantity)}
                    </p>
                  </div>
                </div>

                <div className="flex items-center justify-between mt-3">
                  <div className="flex items-center gap-2">
                    <Button
                      size="icon"
                      variant="outline"
                      className="h-8 w-8"
                      onClick={() => onUpdateQuantity(item.id, Math.max(1, item.quantity - 1))}
                    >
                      <Minus className="h-3 w-3" />
                    </Button>
                    <span className="w-12 text-center font-medium">{item.quantity}</span>
                    <Button
                      size="icon"
                      variant="outline"
                      className="h-8 w-8"
                      onClick={() => onUpdateQuantity(item.id, item.quantity + 1)}
                    >
                      <Plus className="h-3 w-3" />
                    </Button>
                  </div>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="text-destructive"
                    onClick={() => onRemoveItem(item.id)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              <div 
                className={cn(
                  "absolute right-0 top-0 bottom-0 w-20 bg-destructive flex items-center justify-center transition-opacity",
                  swipedItem === item.id ? "opacity-100" : "opacity-0"
                )}
                onClick={() => {
                  onRemoveItem(item.id)
                  setSwipedItem(null)
                }}
              >
                <Trash2 className="h-5 w-5 text-white" />
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="border-t bg-background p-4 space-y-3 pb-20 md:pb-4">
        <div className="space-y-2">
          <div className="flex justify-between text-sm">
            <span>Subtotal</span>
            <span>{formatCurrency(calculateSubtotal())}</span>
          </div>
          {taxMode === "exclusive" && (
            <div className="flex justify-between text-sm">
              <span>VAT (15%)</span>
              <span>{formatCurrency(calculateTax(calculateSubtotal()))}</span>
            </div>
          )}
          <div className="flex justify-between font-bold text-lg pt-2 border-t">
            <span>Total</span>
            <span className="text-primary">{formatCurrency(calculateTotal())}</span>
          </div>
          {taxMode === "inclusive" && (
            <p className="text-xs text-muted-foreground">Includes VAT</p>
          )}
        </div>

        <Button
          className="w-full h-12 text-base font-semibold"
          onClick={onCheckout}
          disabled={!selectedCustomer || cart.length === 0}
        >
          <CreditCard className="mr-2 h-5 w-5" />
          Checkout {formatCurrency(calculateTotal())}
        </Button>

        {!selectedCustomer && (
          <p className="text-xs text-center text-destructive">
            Please select a customer to proceed
          </p>
        )}
      </div>
    </div>
  )
}
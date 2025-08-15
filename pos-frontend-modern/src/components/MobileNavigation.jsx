import React from 'react'
import { ShoppingCart, Grid3x3, Users, Settings, Home } from 'lucide-react'
import { Badge } from './ui/badge'
import { cn } from '../lib/utils'

export function MobileNavigation({ activeTab, setActiveTab, cartItemCount }) {
  const tabs = [
    { id: 'products', icon: Home, label: 'Shop' },
    { id: 'cart', icon: ShoppingCart, label: 'Cart', badge: cartItemCount },
    { id: 'customers', icon: Users, label: 'Customer' },
    { id: 'settings', icon: Settings, label: 'More' },
  ]

  return (
    <nav className="fixed bottom-0 left-0 right-0 bg-background border-t md:hidden z-50">
      <div className="grid grid-cols-4 h-16">
        {tabs.map((tab) => {
          const Icon = tab.icon
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                "flex flex-col items-center justify-center gap-1 relative transition-colors",
                activeTab === tab.id 
                  ? "text-primary" 
                  : "text-muted-foreground"
              )}
            >
              <div className="relative">
                <Icon className="h-5 w-5" />
                {tab.badge > 0 && (
                  <div className="absolute -top-2 -right-2 bg-primary text-primary-foreground rounded-full min-w-[18px] h-[18px] flex items-center justify-center text-xs font-bold px-1">
                    {tab.badge}
                  </div>
                )}
              </div>
              <span className="text-xs">{tab.label}</span>
              {activeTab === tab.id && (
                <div className="absolute top-0 left-0 right-0 h-0.5 bg-primary" />
              )}
            </button>
          )
        })}
      </div>
    </nav>
  )
}
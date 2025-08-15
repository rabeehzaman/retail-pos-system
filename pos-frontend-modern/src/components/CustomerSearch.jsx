import React, { useState, useEffect, useMemo } from 'react'
import { Search, Users, Check, X } from 'lucide-react'
import { Input } from './ui/input'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { cn } from '../lib/utils'

export function CustomerSearch({ 
  customers, 
  selectedCustomer, 
  onSelectCustomer,
  onClose,
  isFullScreen = true 
}) {
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedLetter, setSelectedLetter] = useState(null)

  // Filter customers based on search term or selected letter
  const filteredCustomers = useMemo(() => {
    let filtered = customers

    if (searchTerm) {
      filtered = customers.filter(customer => 
        customer.display_name.toLowerCase().includes(searchTerm.toLowerCase())
      )
    } else if (selectedLetter) {
      filtered = customers.filter(customer => 
        customer.display_name.toUpperCase().startsWith(selectedLetter)
      )
    }

    return filtered.slice(0, 100) // Limit to 100 results for performance
  }, [customers, searchTerm, selectedLetter])

  // Generate alphabet for quick navigation
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('')

  // Get customer initials for quick jump
  const availableLetters = useMemo(() => {
    const letters = new Set()
    customers.forEach(customer => {
      const firstLetter = customer.display_name[0]?.toUpperCase()
      if (firstLetter && alphabet.includes(firstLetter)) {
        letters.add(firstLetter)
      }
    })
    return letters
  }, [customers])

  const handleSelectCustomer = (customer) => {
    onSelectCustomer(customer)
    if (onClose) onClose()
  }

  return (
    <div className={cn(
      "flex flex-col",
      isFullScreen ? "h-full" : ""
    )}>
      {/* Header */}
      <div className="p-4 border-b bg-background sticky top-0 z-10">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Users className="h-5 w-5" />
            Select Customer
          </h2>
          {onClose && (
            <Button
              variant="ghost"
              size="icon"
              onClick={onClose}
              className="h-8 w-8"
            >
              <X className="h-4 w-4" />
            </Button>
          )}
        </div>

        {/* Search Input */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            type="text"
            placeholder="Search customers..."
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value)
              setSelectedLetter(null)
            }}
            className="pl-10 h-10"
            autoFocus
          />
        </div>

        {/* Quick Letter Navigation */}
        <div className="flex flex-wrap gap-1 mt-3">
          {alphabet.map(letter => (
            <button
              key={letter}
              onClick={() => {
                setSelectedLetter(letter === selectedLetter ? null : letter)
                setSearchTerm('')
              }}
              disabled={!availableLetters.has(letter)}
              className={cn(
                "w-8 h-8 text-xs font-semibold rounded transition-colors",
                selectedLetter === letter
                  ? "bg-primary text-primary-foreground"
                  : availableLetters.has(letter)
                  ? "bg-secondary hover:bg-secondary/80"
                  : "bg-muted text-muted-foreground opacity-50 cursor-not-allowed"
              )}
            >
              {letter}
            </button>
          ))}
        </div>

        {/* Current Selection */}
        {selectedCustomer && (
          <div className="mt-3 p-2 bg-primary/10 rounded-lg flex items-center justify-between">
            <span className="text-sm font-medium flex items-center gap-2">
              <Check className="h-4 w-4 text-primary" />
              {selectedCustomer.display_name}
            </span>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => onSelectCustomer(null)}
              className="h-7 text-xs"
            >
              Clear
            </Button>
          </div>
        )}
      </div>

      {/* Customer List */}
      <div className="flex-1 overflow-y-auto">
        {filteredCustomers.length === 0 ? (
          <div className="p-8 text-center">
            <Users className="h-12 w-12 text-muted-foreground mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">
              {searchTerm || selectedLetter 
                ? "No customers found matching your search" 
                : "No customers available"}
            </p>
          </div>
        ) : (
          <div className="p-2">
            {filteredCustomers.map(customer => (
              <button
                key={customer.id}
                onClick={() => handleSelectCustomer(customer)}
                className={cn(
                  "w-full p-3 text-left rounded-lg transition-colors mb-1",
                  "hover:bg-accent active:scale-[0.98] touch-manipulation",
                  selectedCustomer?.id === customer.id
                    ? "bg-primary/10 border border-primary/20"
                    : "bg-card border border-border"
                )}
              >
                <div className="flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-sm truncate">
                      {customer.display_name}
                    </p>
                    {customer.email && (
                      <p className="text-xs text-muted-foreground truncate">
                        {customer.email}
                      </p>
                    )}
                  </div>
                  {selectedCustomer?.id === customer.id && (
                    <Check className="h-4 w-4 text-primary shrink-0 ml-2" />
                  )}
                </div>
              </button>
            ))}
          </div>
        )}

        {/* Load More Indicator */}
        {filteredCustomers.length === 100 && (
          <div className="p-4 text-center text-sm text-muted-foreground">
            Showing first 100 results. Please refine your search.
          </div>
        )}
      </div>

      {/* Footer Actions - Only on mobile */}
      {isFullScreen && (
        <div className="border-t p-4 bg-background">
          <Button
            className="w-full"
            onClick={() => onClose && onClose()}
            disabled={!selectedCustomer}
          >
            Confirm Selection
          </Button>
        </div>
      )}
    </div>
  )
}
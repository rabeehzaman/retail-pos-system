import React from 'react'
import { Plus, Package, Loader2 } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { cn } from '../lib/utils'

export function ProductGrid({ 
  items, 
  onAddToCart, 
  formatCurrency, 
  taxMode,
  viewMode = 'grid',
  isMobile = false,
  isLoading = false 
}) {
  if (isLoading) {
    return (
      <Card className="glass-card">
        <CardContent className="flex flex-col items-center justify-center py-12">
          <Loader2 className="h-12 w-12 text-muted-foreground mb-4 animate-spin" />
          <p className="text-lg font-medium">Loading products...</p>
          <p className="text-sm text-muted-foreground">Please wait while we fetch your inventory</p>
        </CardContent>
      </Card>
    )
  }

  if (items.length === 0) {
    return (
      <Card className="glass-card">
        <CardContent className="flex flex-col items-center justify-center py-12">
          <Package className="h-12 w-12 text-muted-foreground mb-4" />
          <p className="text-lg font-medium">No products found</p>
          <p className="text-sm text-muted-foreground">Try adjusting your search or filters</p>
        </CardContent>
      </Card>
    )
  }

  if (viewMode === 'list') {
    return (
      <div className="space-y-2 px-4 md:px-0">
        {items.map(item => (
          <button
            key={item.id}
            className="w-full flex items-center justify-between p-4 bg-card border rounded-lg active:scale-[0.98] transition-all touch-manipulation hover:bg-accent/50"
            onClick={() => onAddToCart(item)}
          >
            <div className="flex items-center flex-1 text-left">
              <div className="flex-1 min-w-0">
                <h3 className="font-medium text-base truncate">{item.name}</h3>
                <p className="text-sm text-muted-foreground">SKU: {item.sku || 'N/A'}</p>
              </div>
            </div>
            
            <div className="flex items-center gap-3">
              {item.stock_on_hand && (
                <Badge 
                  variant={item.stock_on_hand > 10 ? "success" : "warning"} 
                  className="text-xs"
                >
                  {item.stock_on_hand}
                </Badge>
              )}
              <div className="text-right">
                <div className="font-bold text-lg text-primary">
                  {formatCurrency(
                    taxMode === "inclusive" 
                      ? (item.price || item.rate || item.selling_price || 0) * 1.15 
                      : (item.price || item.rate || item.selling_price || 0)
                  )}
                </div>
                <div className="text-xs text-muted-foreground">per PCS</div>
              </div>
              <div className="ml-2 p-2 bg-primary/10 rounded-full">
                <Plus className="h-5 w-5 text-primary" />
              </div>
            </div>
          </button>
        ))}
      </div>
    )
  }

  return (
    <div className={cn(
      "grid gap-3 px-4 md:px-0",
      isMobile 
        ? "grid-cols-2" 
        : "grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 2xl:grid-cols-8"
    )}>
      {items.map(item => (
        <Card 
          key={item.id} 
          className="product-card cursor-pointer active:scale-[0.98] transition-transform touch-manipulation hover:shadow-lg"
          onClick={() => onAddToCart(item)}
        >
          <CardHeader className="pb-3 p-3">
            <div className="flex items-start justify-between gap-2">
              <CardTitle className="text-sm font-medium line-clamp-2 flex-1">
                {item.name}
              </CardTitle>
              {item.stock_on_hand !== undefined && (
                <Badge 
                  variant={item.stock_on_hand > 10 ? "success" : item.stock_on_hand > 0 ? "warning" : "destructive"}
                  className="text-xs shrink-0"
                >
                  {item.stock_on_hand}
                </Badge>
              )}
            </div>
          </CardHeader>
          <CardContent className="pt-0 p-3">
            <div className="space-y-2">
              <div className="text-center">
                <div className="text-xl font-bold text-primary">
                  {formatCurrency(
                    taxMode === "inclusive" 
                      ? (item.price || item.rate || item.selling_price || 0) * 1.15 
                      : (item.price || item.rate || item.selling_price || 0)
                  )}
                </div>
                <div className="text-xs text-muted-foreground">per PCS</div>
              </div>
              <Button 
                size="sm" 
                className="w-full h-10 touch-manipulation" 
                variant="default"
                onClick={(e) => {
                  e.stopPropagation();
                  onAddToCart(item);
                }}
              >
                <Plus className="h-4 w-4 mr-1" />
                Add
              </Button>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
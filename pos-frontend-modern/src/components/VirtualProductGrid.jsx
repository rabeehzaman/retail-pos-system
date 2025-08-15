import React, { memo } from 'react'
import { FixedSizeGrid as Grid } from 'react-window'
import { Plus, Package } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { cn } from '../lib/utils'

// Memoized product card to prevent unnecessary re-renders
const ProductCard = memo(({ data, columnIndex, rowIndex, style }) => {
  const { items, columnCount, onAddToCart, formatCurrency, taxMode } = data
  const index = rowIndex * columnCount + columnIndex
  const item = items[index]

  if (!item) return <div style={style} />

  const price = taxMode === "inclusive" 
    ? (item.price || item.rate || item.selling_price || 0) * 1.15 
    : (item.price || item.rate || item.selling_price || 0)

  return (
    <div style={style} className="p-2">
      <Card 
        className="h-full product-card cursor-pointer active:scale-[0.98] transition-transform touch-manipulation hover:shadow-lg"
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
                {formatCurrency(price)}
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
    </div>
  )
})

ProductCard.displayName = 'ProductCard'

export function VirtualProductGrid({ 
  items, 
  onAddToCart, 
  formatCurrency, 
  taxMode,
  viewMode = 'grid',
  isMobile = false,
  isLoading = false,
  containerHeight = 600,
  containerWidth = null
}) {
  // Calculate grid dimensions based on screen size
  const columnCount = isMobile ? 2 : 
    containerWidth < 640 ? 2 :
    containerWidth < 768 ? 3 :
    containerWidth < 1024 ? 4 :
    containerWidth < 1280 ? 5 :
    containerWidth < 1536 ? 6 : 8

  const columnWidth = containerWidth / columnCount
  const rowHeight = isMobile ? 250 : 280
  const rowCount = Math.ceil(items.length / columnCount)

  if (isLoading) {
    return (
      <Card className="glass-card">
        <CardContent className="flex flex-col items-center justify-center py-12">
          <div className="h-12 w-12 border-4 border-primary border-t-transparent rounded-full animate-spin mb-4" />
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

  // List view with virtual scrolling
  if (viewMode === 'list') {
    return (
      <VirtualList
        items={items}
        onAddToCart={onAddToCart}
        formatCurrency={formatCurrency}
        taxMode={taxMode}
        height={containerHeight}
        width={containerWidth}
      />
    )
  }

  // Grid view with virtual scrolling
  return (
    <Grid
      className="scrollbar-thin"
      columnCount={columnCount}
      columnWidth={columnWidth}
      height={containerHeight}
      rowCount={rowCount}
      rowHeight={rowHeight}
      width={containerWidth}
      itemData={{
        items,
        columnCount,
        onAddToCart,
        formatCurrency,
        taxMode
      }}
    >
      {ProductCard}
    </Grid>
  )
}

// Virtual list component for list view
const ListItem = memo(({ index, style, data }) => {
  const { items, onAddToCart, formatCurrency, taxMode } = data
  const item = items[index]

  if (!item) return <div style={style} />

  const price = taxMode === "inclusive" 
    ? (item.price || item.rate || item.selling_price || 0) * 1.15 
    : (item.price || item.rate || item.selling_price || 0)

  return (
    <div style={style} className="px-4">
      <button
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
              {formatCurrency(price)}
            </div>
            <div className="text-xs text-muted-foreground">per PCS</div>
          </div>
          <div className="ml-2 p-2 bg-primary/10 rounded-full">
            <Plus className="h-5 w-5 text-primary" />
          </div>
        </div>
      </button>
    </div>
  )
})

ListItem.displayName = 'ListItem'

function VirtualList({ items, onAddToCart, formatCurrency, taxMode, height, width }) {
  const List = require('react-window').FixedSizeList

  return (
    <List
      height={height}
      itemCount={items.length}
      itemSize={88}
      width={width}
      itemData={{
        items,
        onAddToCart,
        formatCurrency,
        taxMode
      }}
    >
      {ListItem}
    </List>
  )
}
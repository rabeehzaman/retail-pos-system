import React, { memo, useState, useEffect } from 'react'
import { FixedSizeGrid as Grid, FixedSizeList as List } from 'react-window'
import { Plus, Package, TrendingUp } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { cn } from '../lib/utils'
import { canHandleLargeLists, getOptimalBatchSize } from '../utils/deviceDetection'

// Loading skeleton component
const ProductSkeleton = () => (
  <Card className="h-full animate-pulse">
    <CardHeader className="pb-3 p-3">
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 space-y-2">
          <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-3/4"></div>
          <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-1/2"></div>
        </div>
        <div className="h-6 w-12 bg-gray-200 dark:bg-gray-700 rounded"></div>
      </div>
    </CardHeader>
    <CardContent className="pt-0 p-3">
      <div className="space-y-2">
        <div className="text-center space-y-1">
          <div className="h-6 bg-gray-200 dark:bg-gray-700 rounded w-20 mx-auto"></div>
          <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-16 mx-auto"></div>
        </div>
        <div className="h-10 bg-gray-200 dark:bg-gray-700 rounded"></div>
      </div>
    </CardContent>
  </Card>
)

// Memoized product card to prevent unnecessary re-renders
const ProductCard = memo(({ data, columnIndex, rowIndex, style }) => {
  const { items, columnCount, onAddToCart, formatCurrency, taxMode, onProductSales, selectedIndex } = data
  const index = rowIndex * columnCount + columnIndex
  const item = items[index]
  const isSelected = index === selectedIndex

  if (!item) return <div style={style} />

  const price = taxMode === "inclusive" 
    ? (item.price || item.rate || item.selling_price || 0) * 1.15 
    : (item.price || item.rate || item.selling_price || 0)

  return (
    <div style={style} className="p-1.5">
      <Card 
        className={cn(
          "h-full product-card cursor-pointer active:scale-[0.98] transition-all touch-manipulation hover:shadow-lg flex flex-col",
          isSelected && "ring-2 ring-primary shadow-lg scale-105"
        )}
        onClick={() => onAddToCart(item)}
      >
        <CardHeader className="pb-2 p-3 flex-shrink-0">
          <div className="flex items-start justify-between gap-2">
            <CardTitle className="text-sm font-medium line-clamp-2 flex-1 leading-tight">
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
        <CardContent className="pt-0 p-3 flex-1 flex flex-col justify-between">
          <div className="text-center mb-3">
            <div className="text-lg font-bold text-primary leading-tight">
              {formatCurrency(price)}
            </div>
            <div className="text-xs text-muted-foreground">per PCS</div>
          </div>
          <div className="flex gap-1 mt-auto">
              {onProductSales && (
                <Button 
                  size="sm" 
                  variant="ghost" 
                  className="h-8 flex-1 px-2"
                  onClick={(e) => {
                    e.stopPropagation();
                    onProductSales(item);
                  }}
                  title="View Sales History"
                >
                  <TrendingUp className="h-3.5 w-3.5" />
                </Button>
              )}
              <Button 
                size="sm" 
                className={`h-8 touch-manipulation text-xs ${onProductSales ? 'flex-2' : 'w-full'}`}
                variant="default"
                onClick={(e) => {
                  e.stopPropagation();
                  onAddToCart(item);
                }}
              >
                <Plus className="h-3.5 w-3.5 mr-1" />
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
  containerWidth = null,
  onProductSales = null,
  selectedIndex = -1
}) {
  // Check if device can handle large lists
  const [currentPage, setCurrentPage] = useState(1)
  const canUseVirtualScroll = canHandleLargeLists()
  const batchSize = getOptimalBatchSize()
  const shouldPaginate = !canUseVirtualScroll && items.length > batchSize
  
  // Calculate paginated items if needed
  const displayItems = shouldPaginate 
    ? items.slice((currentPage - 1) * batchSize, currentPage * batchSize)
    : items
  const totalPages = shouldPaginate ? Math.ceil(items.length / batchSize) : 1
  // Calculate grid dimensions based on screen size with fallback
  const actualWidth = containerWidth || window.innerWidth
  const actualHeight = containerHeight || 600
  
  // Better responsive grid with min/max card sizes
  const minCardWidth = 150
  const maxCardWidth = 250
  const idealCardWidth = 200
  
  const columnCount = isMobile ? 2 : Math.max(
    2, 
    Math.min(
      8, // Max 8 columns
      Math.floor(actualWidth / minCardWidth)
    )
  )

  const columnWidth = Math.max(minCardWidth, Math.min(maxCardWidth, actualWidth / columnCount))
  // More compact aspect ratio - reduce height significantly
  const rowHeight = isMobile ? Math.ceil(columnWidth * 1.2) : Math.ceil(columnWidth * 0.95)
  const rowCount = Math.ceil(displayItems.length / columnCount)
  
  // Prevent rendering if dimensions are invalid
  if (actualWidth === 0 || !columnWidth || isNaN(columnWidth)) {
    return (
      <Card className="glass-card">
        <CardContent className="flex flex-col items-center justify-center py-12">
          <div className="h-12 w-12 border-4 border-primary border-t-transparent rounded-full animate-spin mb-4" />
          <p className="text-lg font-medium">Initializing...</p>
        </CardContent>
      </Card>
    )
  }

  if (isLoading) {
    // Show skeleton grid while loading
    const skeletonCount = Math.min(12, Math.floor((actualHeight / rowHeight) * columnCount))
    return (
      <div className={cn(
        "grid gap-3 px-4 md:px-0",
        isMobile 
          ? "grid-cols-2" 
          : "grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 2xl:grid-cols-8"
      )}>
        {Array.from({ length: skeletonCount }).map((_, index) => (
          <ProductSkeleton key={index} />
        ))}
      </div>
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
      <>
        <VirtualList
          items={displayItems}
          onAddToCart={onAddToCart}
          formatCurrency={formatCurrency}
          taxMode={taxMode}
          height={shouldPaginate ? actualHeight - 60 : actualHeight}
          width={actualWidth}
          onProductSales={onProductSales}
        />
        {shouldPaginate && (
          <div className="flex items-center justify-between p-4 border-t">
            <Button 
              variant="outline" 
              size="sm"
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              disabled={currentPage === 1}
            >
              Previous
            </Button>
            <span className="text-sm text-muted-foreground">
              Page {currentPage} of {totalPages} ({items.length} products)
            </span>
            <Button 
              variant="outline" 
              size="sm"
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
            >
              Next
            </Button>
          </div>
        )}
      </>
    )
  }

  // Grid view with virtual scrolling or pagination
  return (
    <>
      <Grid
        className="scrollbar-thin"
        columnCount={columnCount}
        columnWidth={columnWidth}
        height={shouldPaginate ? actualHeight - 60 : actualHeight}
        rowCount={rowCount}
        rowHeight={rowHeight}
        width={actualWidth}
        itemData={{
          items: displayItems,
          columnCount,
          onAddToCart,
          formatCurrency,
          taxMode,
          onProductSales,
          selectedIndex
        }}
      >
        {ProductCard}
      </Grid>
      {shouldPaginate && (
        <div className="flex items-center justify-between p-4 border-t bg-background">
          <Button 
            variant="outline" 
            size="sm"
            onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
            disabled={currentPage === 1}
          >
            Previous
          </Button>
          <span className="text-sm text-muted-foreground">
            Page {currentPage} of {totalPages} ({items.length} products)
          </span>
          <Button 
            variant="outline" 
            size="sm"
            onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
            disabled={currentPage === totalPages}
          >
            Next
          </Button>
        </div>
      )}
    </>
  )
}

// Virtual list component for list view
const ListItem = memo(({ index, style, data }) => {
  const { items, onAddToCart, formatCurrency, taxMode, onProductSales } = data
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
        <div className="flex items-center flex-1 text-left min-w-0 overflow-hidden">
          <div className="flex-1 min-w-0">
            <h3 className="font-medium text-base truncate">{item.name}</h3>
            <p className="text-sm text-muted-foreground truncate">SKU: {item.sku || 'N/A'}</p>
          </div>
        </div>
        
        <div className="flex items-center gap-3 shrink-0">
          {onProductSales && (
            <Button 
              size="icon" 
              variant="ghost" 
              className="h-7 w-7"
              onClick={(e) => {
                e.stopPropagation();
                onProductSales(item);
              }}
              title="View Sales History"
            >
              <TrendingUp className="h-3 w-3" />
            </Button>
          )}
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

function VirtualList({ items, onAddToCart, formatCurrency, taxMode, height, width, onProductSales }) {
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
        taxMode,
        onProductSales
      }}
    >
      {ListItem}
    </List>
  )
}
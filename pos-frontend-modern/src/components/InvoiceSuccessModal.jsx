import React from 'react'
import { CheckCircle, Download, ShoppingCart, Eye } from 'lucide-react'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from './ui/dialog'
import { Button } from './ui/button'
import { Badge } from './ui/badge'

const InvoiceSuccessModal = ({ 
  isOpen, 
  onClose, 
  invoice, 
  formatCurrency, 
  onDownload, 
  onNewSale,
  isDownloading = false 
}) => {
  if (!invoice) return null

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-emerald-100 dark:bg-emerald-900">
            <CheckCircle className="h-6 w-6 text-emerald-600 dark:text-emerald-400" />
          </div>
          <DialogTitle className="text-center">
            Invoice Created Successfully!
          </DialogTitle>
        </DialogHeader>
        
        <div className="space-y-4">
          {/* Invoice Details */}
          <div className="rounded-lg border bg-muted/50 p-4">
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium">Invoice Number:</span>
                <span className="text-sm font-mono">{invoice.invoice_number}</span>
              </div>
              
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium">Total Amount:</span>
                <span className="text-sm font-bold">{formatCurrency(invoice.total)}</span>
              </div>
              
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium">Status:</span>
                <Badge variant={invoice.status === 'sent' ? 'default' : 'secondary'}>
                  {invoice.status || 'Draft'}
                </Badge>
              </div>
              
              {invoice.pending && (
                <div className="flex justify-between items-center">
                  <span className="text-sm font-medium">Sync Status:</span>
                  <Badge variant="warning">Pending Sync</Badge>
                </div>
              )}
            </div>
          </div>

          {/* Action Buttons */}
          <div className="grid grid-cols-1 gap-3">
            {!invoice.pending && (
              <Button
                onClick={onDownload}
                disabled={isDownloading}
                className="w-full bg-emerald-600 hover:bg-emerald-700 text-white"
              >
                <Download className="mr-2 h-4 w-4" />
                {isDownloading ? 'Downloading...' : 'Download PDF'}
              </Button>
            )}
            
            <Button
              onClick={onNewSale}
              variant="outline"
              className="w-full"
            >
              <ShoppingCart className="mr-2 h-4 w-4" />
              Start New Sale
            </Button>
          </div>

          {invoice.pending && (
            <div className="text-center p-3 bg-amber-50 dark:bg-amber-950 rounded-lg border border-amber-200 dark:border-amber-800">
              <p className="text-sm text-amber-800 dark:text-amber-200">
                📱 You're offline! This invoice will sync when you're back online.
              </p>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}

export default InvoiceSuccessModal
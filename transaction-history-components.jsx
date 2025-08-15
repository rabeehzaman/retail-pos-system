// Sample React components for transaction history feature
// Add these to your pos-frontend-modern/src/components folder

import React, { useState, useEffect } from 'react';
import { X, History, TrendingUp, Package, RefreshCw, Download, Eye } from 'lucide-react';

// ==================== CUSTOMER HISTORY MODAL ====================

export const CustomerHistoryModal = ({ customer, isOpen, onClose, backendUrl }) => {
  const [invoices, setInvoices] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedInvoice, setSelectedInvoice] = useState(null);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(false);

  useEffect(() => {
    if (isOpen && customer) {
      fetchCustomerInvoices();
    }
  }, [isOpen, customer, page]);

  const fetchCustomerInvoices = async () => {
    if (!customer?.contact_id) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(
        `${backendUrl}/api/customers/${customer.contact_id}/invoices?page=${page}&per_page=20`,
        {
          headers: {
            'Content-Type': 'application/json'
          }
        }
      );
      
      if (!response.ok) throw new Error('Failed to fetch invoices');
      
      const data = await response.json();
      
      if (page === 1) {
        setInvoices(data.invoices);
      } else {
        setInvoices(prev => [...prev, ...data.invoices]);
      }
      
      setHasMore(data.pagination.has_more_page);
    } catch (err) {
      setError(err.message);
      console.error('Error fetching customer invoices:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchInvoiceDetails = async (invoiceId) => {
    try {
      const response = await fetch(
        `${backendUrl}/api/invoices/${invoiceId}/details`,
        {
          headers: {
            'Content-Type': 'application/json'
          }
        }
      );
      
      if (!response.ok) throw new Error('Failed to fetch invoice details');
      
      const data = await response.json();
      setSelectedInvoice(data.invoice);
    } catch (err) {
      console.error('Error fetching invoice details:', err);
    }
  };

  const handleReorder = (invoice) => {
    // This would add items from the invoice to the current cart
    console.log('Reorder invoice:', invoice);
    // Implementation would depend on your cart management
  };

  const formatCurrency = (amount) => {
    return new Intl.NumberFormat('en-SA', {
      style: 'currency',
      currency: 'SAR'
    }).format(amount);
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-4xl max-h-[80vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b">
          <div>
            <h2 className="text-2xl font-bold flex items-center gap-2">
              <History className="w-6 h-6" />
              Customer Purchase History
            </h2>
            <p className="text-gray-600 mt-1">
              {customer?.contact_name || customer?.company_name}
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto max-h-[60vh]">
          {loading && page === 1 ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
              <p className="mt-4 text-gray-600">Loading purchase history...</p>
            </div>
          ) : error ? (
            <div className="text-center py-8">
              <p className="text-red-600">{error}</p>
              <button
                onClick={fetchCustomerInvoices}
                className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                Retry
              </button>
            </div>
          ) : invoices.length === 0 ? (
            <div className="text-center py-8">
              <Package className="w-16 h-16 text-gray-400 mx-auto" />
              <p className="mt-4 text-gray-600">No purchase history found</p>
            </div>
          ) : (
            <>
              {/* Summary Stats */}
              <div className="grid grid-cols-3 gap-4 mb-6">
                <div className="bg-blue-50 p-4 rounded-lg">
                  <p className="text-sm text-blue-600 font-medium">Total Purchases</p>
                  <p className="text-2xl font-bold text-blue-900">{invoices.length}</p>
                </div>
                <div className="bg-green-50 p-4 rounded-lg">
                  <p className="text-sm text-green-600 font-medium">Total Spent</p>
                  <p className="text-2xl font-bold text-green-900">
                    {formatCurrency(invoices.reduce((sum, inv) => sum + parseFloat(inv.total || 0), 0))}
                  </p>
                </div>
                <div className="bg-purple-50 p-4 rounded-lg">
                  <p className="text-sm text-purple-600 font-medium">Last Purchase</p>
                  <p className="text-2xl font-bold text-purple-900">
                    {invoices[0] ? formatDate(invoices[0].date) : 'N/A'}
                  </p>
                </div>
              </div>

              {/* Invoice List */}
              <div className="space-y-3">
                {invoices.map((invoice) => (
                  <div
                    key={invoice.invoice_id}
                    className="border rounded-lg p-4 hover:bg-gray-50 transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-4">
                          <span className="font-semibold text-lg">
                            {invoice.invoice_number}
                          </span>
                          <span className="text-gray-600">
                            {formatDate(invoice.date)}
                          </span>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                            invoice.status === 'paid' 
                              ? 'bg-green-100 text-green-800'
                              : invoice.status === 'overdue'
                              ? 'bg-red-100 text-red-800'
                              : 'bg-yellow-100 text-yellow-800'
                          }`}>
                            {invoice.status}
                          </span>
                        </div>
                        <div className="mt-2 text-sm text-gray-600">
                          {invoice.line_items_count} items • {formatCurrency(invoice.total)}
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <button
                          onClick={() => fetchInvoiceDetails(invoice.invoice_id)}
                          className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                          title="View Details"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleReorder(invoice)}
                          className="p-2 text-green-600 hover:bg-green-50 rounded-lg transition-colors"
                          title="Reorder"
                        >
                          <RefreshCw className="w-4 h-4" />
                        </button>
                        <a
                          href={`${backendUrl}/api/invoices/${invoice.invoice_id}/download`}
                          className="p-2 text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
                          title="Download PDF"
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          <Download className="w-4 h-4" />
                        </a>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Load More */}
              {hasMore && (
                <div className="mt-6 text-center">
                  <button
                    onClick={() => setPage(prev => prev + 1)}
                    disabled={loading}
                    className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                  >
                    {loading ? 'Loading...' : 'Load More'}
                  </button>
                </div>
              )}
            </>
          )}
        </div>

        {/* Invoice Details Modal */}
        {selectedInvoice && (
          <InvoiceDetailsModal
            invoice={selectedInvoice}
            onClose={() => setSelectedInvoice(null)}
            formatCurrency={formatCurrency}
            formatDate={formatDate}
          />
        )}
      </div>
    </div>
  );
};

// ==================== INVOICE DETAILS MODAL ====================

const InvoiceDetailsModal = ({ invoice, onClose, formatCurrency, formatDate }) => {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-[60]">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-3xl max-h-[80vh] overflow-hidden">
        <div className="flex items-center justify-between p-6 border-b">
          <h3 className="text-xl font-bold">Invoice {invoice.invoice_number}</h3>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        
        <div className="p-6 overflow-y-auto max-h-[60vh]">
          {/* Invoice Header */}
          <div className="mb-6">
            <p className="text-gray-600">Date: {formatDate(invoice.date)}</p>
            <p className="text-gray-600">Customer: {invoice.customer_details?.customer_name}</p>
            <p className="text-gray-600">Status: {invoice.status}</p>
          </div>

          {/* Line Items */}
          <div className="border rounded-lg overflow-hidden">
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-2 text-left">Item</th>
                  <th className="px-4 py-2 text-center">Qty</th>
                  <th className="px-4 py-2 text-right">Rate</th>
                  <th className="px-4 py-2 text-right">Total</th>
                </tr>
              </thead>
              <tbody>
                {invoice.line_items?.map((item, index) => (
                  <tr key={index} className="border-t">
                    <td className="px-4 py-2">
                      <div>
                        <p className="font-medium">{item.name}</p>
                        {item.description && (
                          <p className="text-sm text-gray-600">{item.description}</p>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-2 text-center">
                      {item.quantity} {item.unit}
                    </td>
                    <td className="px-4 py-2 text-right">
                      {formatCurrency(item.rate)}
                    </td>
                    <td className="px-4 py-2 text-right">
                      {formatCurrency(item.item_total)}
                    </td>
                  </tr>
                ))}
              </tbody>
              <tfoot className="bg-gray-50">
                <tr>
                  <td colSpan="3" className="px-4 py-2 text-right font-bold">
                    Total:
                  </td>
                  <td className="px-4 py-2 text-right font-bold">
                    {formatCurrency(invoice.total)}
                  </td>
                </tr>
              </tfoot>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

// ==================== PRODUCT SALES HISTORY DRAWER ====================

export const ProductSalesDrawer = ({ product, isOpen, onClose, backendUrl }) => {
  const [salesData, setSalesData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [dateRange, setDateRange] = useState('30'); // days

  useEffect(() => {
    if (isOpen && product) {
      fetchProductSales();
    }
  }, [isOpen, product, dateRange]);

  const fetchProductSales = async () => {
    if (!product?.id) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const fromDate = new Date();
      fromDate.setDate(fromDate.getDate() - parseInt(dateRange));
      
      const response = await fetch(
        `${backendUrl}/api/items/${product.id}/sales?from_date=${fromDate.toISOString().split('T')[0]}`,
        {
          headers: {
            'Content-Type': 'application/json'
          }
        }
      );
      
      if (!response.ok) throw new Error('Failed to fetch sales data');
      
      const data = await response.json();
      setSalesData(data);
    } catch (err) {
      setError(err.message);
      console.error('Error fetching product sales:', err);
    } finally {
      setLoading(false);
    }
  };

  const formatCurrency = (amount) => {
    return new Intl.NumberFormat('en-SA', {
      style: 'currency',
      currency: 'SAR'
    }).format(amount);
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric'
    });
  };

  if (!isOpen) return null;

  return (
    <div className={`fixed right-0 top-0 h-full w-96 bg-white shadow-2xl transform transition-transform duration-300 z-50 ${
      isOpen ? 'translate-x-0' : 'translate-x-full'
    }`}>
      {/* Header */}
      <div className="p-6 border-b">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xl font-bold flex items-center gap-2">
            <TrendingUp className="w-5 h-5" />
            Sales Analytics
          </h3>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="text-sm text-gray-600">
          {product?.name}
        </div>
        
        {/* Date Range Selector */}
        <div className="mt-4 flex gap-2">
          {['7', '30', '90'].map((days) => (
            <button
              key={days}
              onClick={() => setDateRange(days)}
              className={`px-3 py-1 rounded-lg text-sm font-medium transition-colors ${
                dateRange === days
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              {days} days
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="p-6 overflow-y-auto" style={{ maxHeight: 'calc(100vh - 200px)' }}>
        {loading ? (
          <div className="text-center py-8">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
            <p className="mt-4 text-gray-600">Loading sales data...</p>
          </div>
        ) : error ? (
          <div className="text-center py-8">
            <p className="text-red-600">{error}</p>
            <button
              onClick={fetchProductSales}
              className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Retry
            </button>
          </div>
        ) : salesData ? (
          <>
            {/* Summary Stats */}
            <div className="space-y-4 mb-6">
              <div className="bg-blue-50 p-4 rounded-lg">
                <p className="text-sm text-blue-600 font-medium">Total Sold</p>
                <p className="text-2xl font-bold text-blue-900">
                  {salesData.summary.total_quantity_sold} units
                </p>
              </div>
              <div className="bg-green-50 p-4 rounded-lg">
                <p className="text-sm text-green-600 font-medium">Total Revenue</p>
                <p className="text-2xl font-bold text-green-900">
                  {formatCurrency(salesData.summary.total_revenue)}
                </p>
              </div>
              <div className="bg-purple-50 p-4 rounded-lg">
                <p className="text-sm text-purple-600 font-medium">Avg. per Sale</p>
                <p className="text-2xl font-bold text-purple-900">
                  {salesData.summary.average_quantity_per_sale} units
                </p>
              </div>
            </div>

            {/* Top Customers */}
            {salesData.summary.top_customers.length > 0 && (
              <div className="mb-6">
                <h4 className="font-semibold mb-3">Top Customers</h4>
                <div className="space-y-2">
                  {salesData.summary.top_customers.slice(0, 5).map((customer, index) => (
                    <div key={index} className="flex items-center justify-between p-2 bg-gray-50 rounded-lg">
                      <div>
                        <p className="font-medium text-sm">{customer.customer_name}</p>
                        <p className="text-xs text-gray-600">
                          {customer.purchase_count} orders • {customer.total_quantity} units
                        </p>
                      </div>
                      <p className="font-semibold text-sm">
                        {formatCurrency(customer.total_value)}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Recent Sales */}
            <div>
              <h4 className="font-semibold mb-3">Recent Sales</h4>
              <div className="space-y-2">
                {salesData.sales_history.slice(0, 10).map((sale, index) => (
                  <div key={index} className="p-2 border rounded-lg">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-medium text-sm">{sale.customer_name}</p>
                        <p className="text-xs text-gray-600">
                          {formatDate(sale.date)} • {sale.invoice_number}
                        </p>
                      </div>
                      <div className="text-right">
                        <p className="font-semibold text-sm">
                          {sale.quantity} {sale.unit}
                        </p>
                        <p className="text-xs text-gray-600">
                          {formatCurrency(sale.total)}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </>
        ) : (
          <div className="text-center py-8">
            <Package className="w-16 h-16 text-gray-400 mx-auto" />
            <p className="mt-4 text-gray-600">No sales data available</p>
          </div>
        )}
      </div>
    </div>
  );
};

// ==================== FREQUENT ITEMS COMPONENT ====================

export const FrequentItemsButton = ({ customer, onAddToCart, backendUrl }) => {
  const [frequentItems, setFrequentItems] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showDropdown, setShowDropdown] = useState(false);

  const fetchFrequentItems = async () => {
    if (!customer?.contact_id) return;
    
    setLoading(true);
    
    try {
      const response = await fetch(
        `${backendUrl}/api/customers/${customer.contact_id}/frequent-items`,
        {
          headers: {
            'Content-Type': 'application/json'
          }
        }
      );
      
      if (!response.ok) throw new Error('Failed to fetch frequent items');
      
      const data = await response.json();
      setFrequentItems(data);
      setShowDropdown(true);
    } catch (err) {
      console.error('Error fetching frequent items:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleReorderLast = () => {
    if (frequentItems?.last_order?.items) {
      frequentItems.last_order.items.forEach(item => {
        onAddToCart(item);
      });
      setShowDropdown(false);
    }
  };

  const handleAddFrequentItem = (item) => {
    onAddToCart({
      item_id: item.item_id,
      name: item.name,
      quantity: item.average_quantity,
      // Add other required fields
    });
  };

  if (!customer) return null;

  return (
    <div className="relative">
      <button
        onClick={fetchFrequentItems}
        disabled={loading}
        className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50"
      >
        <RefreshCw className="w-4 h-4" />
        {loading ? 'Loading...' : 'Quick Reorder'}
      </button>

      {showDropdown && frequentItems && (
        <div className="absolute top-full mt-2 right-0 w-80 bg-white border rounded-lg shadow-xl z-50">
          <div className="p-4 border-b">
            <h4 className="font-semibold">Quick Reorder Options</h4>
          </div>
          
          {/* Last Order */}
          {frequentItems.last_order?.items && (
            <div className="p-4 border-b">
              <div className="flex items-center justify-between mb-2">
                <p className="text-sm font-medium">Last Order ({frequentItems.last_order.date})</p>
                <button
                  onClick={handleReorderLast}
                  className="text-xs px-2 py-1 bg-blue-600 text-white rounded hover:bg-blue-700"
                >
                  Add All
                </button>
              </div>
              <div className="space-y-1">
                {frequentItems.last_order.items.slice(0, 3).map((item, index) => (
                  <p key={index} className="text-xs text-gray-600">
                    {item.quantity} × {item.name}
                  </p>
                ))}
              </div>
            </div>
          )}

          {/* Frequent Items */}
          <div className="p-4">
            <p className="text-sm font-medium mb-2">Frequently Bought</p>
            <div className="space-y-2">
              {frequentItems.frequent_items.slice(0, 5).map((item) => (
                <div key={item.item_id} className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium">{item.name}</p>
                    <p className="text-xs text-gray-600">
                      Avg: {item.average_quantity} units
                    </p>
                  </div>
                  <button
                    onClick={() => handleAddFrequentItem(item)}
                    className="text-xs px-2 py-1 border border-blue-600 text-blue-600 rounded hover:bg-blue-50"
                  >
                    Add
                  </button>
                </div>
              ))}
            </div>
          </div>

          <button
            onClick={() => setShowDropdown(false)}
            className="w-full p-2 text-sm text-gray-600 hover:bg-gray-50 border-t"
          >
            Close
          </button>
        </div>
      )}
    </div>
  );
};

// Export all components
export default {
  CustomerHistoryModal,
  ProductSalesDrawer,
  FrequentItemsButton
};
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { X, TrendingUp, User, Users, Package, RefreshCw } from 'lucide-react';

const ProductSalesHistory = ({ 
  isOpen, 
  onClose, 
  product,
  selectedCustomer,
  backendUrl 
}) => {
  const [sales, setSales] = useState([]);
  const [filterByCustomer, setFilterByCustomer] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Fetch sales when modal opens or filter changes
  useEffect(() => {
    if (isOpen && product) {
      fetchProductSales();
    }
  }, [isOpen, product, filterByCustomer]);

  const fetchProductSales = async () => {
    if (!product?.id) return;
    
    setLoading(true);
    setError(null);
    
    try {
      // Build query parameters
      const params = new URLSearchParams();
      
      // Add customer filter if checkbox is checked and customer is selected
      if (filterByCustomer && selectedCustomer) {
        params.append('customer_id', selectedCustomer.contact_id);
      }
      
      console.log(`Fetching sales for product ${product.id}`, params.toString());
      
      const response = await axios.get(
        `${backendUrl}/api/products/${product.id}/sales?${params.toString()}`
      );
      
      if (response.data.success) {
        setSales(response.data.sales || []);
      } else {
        throw new Error('Failed to fetch sales data');
      }
    } catch (err) {
      console.error('Error fetching product sales:', err);
      setError(err.response?.data?.error || err.message || 'Failed to fetch sales history');
      setSales([]);
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    const today = new Date();
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);
    
    // Check if today
    if (date.toDateString() === today.toDateString()) {
      return 'Today';
    }
    // Check if yesterday
    if (date.toDateString() === yesterday.toDateString()) {
      return 'Yesterday';
    }
    
    // Otherwise return formatted date
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: date.getFullYear() !== today.getFullYear() ? 'numeric' : undefined
    });
  };

  const formatQuantity = (quantity, unit) => {
    return `${quantity} ${unit || 'PCS'}`;
  };

  const formatCurrency = (amount) => {
    return `${parseFloat(amount || 0).toFixed(2)} SAR`;
  };

  const getTotalQuantity = () => {
    return sales.reduce((sum, sale) => {
      const qty = parseFloat(sale.quantity) || 0;
      return sum + qty;
    }, 0);
  };

  const getTotalRevenue = () => {
    return sales.reduce((sum, sale) => {
      const total = parseFloat(sale.total) || 0;
      return sum + total;
    }, 0);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-3xl max-h-[80vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b bg-gradient-to-r from-blue-50 to-indigo-50">
          <div>
            <div className="flex items-center gap-2">
              <TrendingUp className="w-5 h-5 text-blue-600" />
              <h2 className="text-lg font-semibold">Sales History</h2>
            </div>
            <p className="text-sm text-gray-600 mt-1 flex items-center gap-2">
              <Package className="w-4 h-4" />
              {product?.name || 'Product'}
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-1 hover:bg-gray-200 rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Filter Section */}
        <div className="p-4 border-b bg-white">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {selectedCustomer && (
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={filterByCustomer}
                    onChange={(e) => setFilterByCustomer(e.target.checked)}
                    className="w-4 h-4 text-blue-600 rounded focus:ring-blue-500"
                  />
                  <span className="text-sm text-gray-700 flex items-center gap-1">
                    <User className="w-4 h-4" />
                    Show only: <span className="font-medium">{selectedCustomer.contact_name || selectedCustomer.company_name}</span>
                  </span>
                </label>
              )}
              {!selectedCustomer && (
                <span className="text-sm text-gray-500 flex items-center gap-1">
                  <Users className="w-4 h-4" />
                  Showing all customers
                </span>
              )}
            </div>
            
            <button
              onClick={fetchProductSales}
              className="text-blue-600 hover:text-blue-700 flex items-center gap-1 text-sm"
            >
              <RefreshCw className="w-3 h-3" />
              Refresh
            </button>
          </div>
        </div>

        {/* Summary Stats */}
        {!loading && !error && sales.length > 0 && (
          <div className="grid grid-cols-2 gap-4 p-4 bg-gray-50">
            <div className="bg-white p-3 rounded-lg border">
              <p className="text-xs text-gray-600">Total Quantity Sold</p>
              <p className="text-xl font-bold text-gray-900">{getTotalQuantity()} units</p>
            </div>
            <div className="bg-white p-3 rounded-lg border">
              <p className="text-xs text-gray-600">Total Revenue</p>
              <p className="text-xl font-bold text-gray-900">{formatCurrency(getTotalRevenue())}</p>
            </div>
          </div>
        )}

        {/* Content */}
        <div className="overflow-y-auto" style={{ maxHeight: 'calc(80vh - 240px)' }}>
          {loading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-blue-600"></div>
              <p className="mt-3 text-gray-600">Loading sales history...</p>
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center py-12 px-4">
              <div className="text-red-500 text-center">
                <p className="font-medium">Error loading sales</p>
                <p className="text-sm mt-1">{error}</p>
              </div>
              <button
                onClick={fetchProductSales}
                className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center gap-2"
              >
                <RefreshCw className="w-4 h-4" />
                Retry
              </button>
            </div>
          ) : sales.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 px-4">
              <Package className="w-12 h-12 text-gray-400 mb-3" />
              <p className="text-gray-600 text-center">
                No sales found for this product
                {filterByCustomer && selectedCustomer && (
                  <span className="block text-sm mt-1">
                    Try unchecking the customer filter to see all sales
                  </span>
                )}
              </p>
            </div>
          ) : (
            <div className="divide-y divide-gray-200">
              {/* Table Header - Desktop */}
              <div className="hidden md:grid md:grid-cols-6 gap-4 px-4 py-3 bg-gray-50 text-sm font-medium text-gray-700">
                <div className="col-span-2">Customer</div>
                <div>Date</div>
                <div className="text-center">Quantity</div>
                <div className="text-right">Unit Price</div>
                <div className="text-right">Invoice</div>
              </div>

              {/* Sales Rows */}
              {sales.map((sale, index) => (
                <div key={`${sale.invoice_id}-${index}`} className="hover:bg-gray-50 transition-colors">
                  {/* Desktop View */}
                  <div className="hidden md:grid md:grid-cols-6 gap-4 px-4 py-3 items-center">
                    <div className="col-span-2 text-gray-800">
                      {sale.customer_name}
                    </div>
                    <div className="text-gray-600 text-sm">
                      {formatDate(sale.date)}
                    </div>
                    <div className="text-center font-medium">
                      {formatQuantity(sale.quantity, sale.unit)}
                    </div>
                    <div className="text-right font-medium">
                      {formatCurrency(sale.rate)}
                    </div>
                    <div className="text-right">
                      <span className="text-sm text-blue-600 hover:text-blue-700">
                        {sale.invoice_number}
                      </span>
                    </div>
                  </div>

                  {/* Mobile View */}
                  <div className="md:hidden px-4 py-3">
                    <div className="flex justify-between items-start mb-2">
                      <div>
                        <div className="font-medium text-gray-800">
                          {sale.customer_name}
                        </div>
                        <div className="text-xs text-gray-500 mt-1">
                          {formatDate(sale.date)}
                        </div>
                      </div>
                      <span className="text-sm text-blue-600">
                        {sale.invoice_number}
                      </span>
                    </div>
                    <div className="flex justify-between items-end">
                      <div className="text-sm text-gray-600">
                        Quantity: <span className="font-medium">{formatQuantity(sale.quantity, sale.unit)}</span>
                      </div>
                      <div className="text-sm font-medium">
                        {formatCurrency(sale.total)}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        {sales.length > 0 && (
          <div className="p-4 border-t bg-gray-50">
            <div className="text-sm text-gray-600">
              Showing {sales.length} sale{sales.length !== 1 ? 's' : ''} 
              {filterByCustomer && selectedCustomer ? 
                ` for ${selectedCustomer.contact_name || selectedCustomer.company_name}` : 
                ' from all customers'}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ProductSalesHistory;
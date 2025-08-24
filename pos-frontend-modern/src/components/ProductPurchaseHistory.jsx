import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { X, TrendingDown, User, Users, Package, RefreshCw } from 'lucide-react';

const ProductPurchaseHistory = ({ 
  isOpen, 
  onClose, 
  product,
  selectedVendor,
  backendUrl 
}) => {
  const [purchases, setPurchases] = useState([]);
  const [filterByVendor, setFilterByVendor] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Fetch purchases when modal opens or filter changes
  useEffect(() => {
    if (isOpen && product) {
      fetchProductPurchases();
    }
  }, [isOpen, product, filterByVendor]);

  const fetchProductPurchases = async () => {
    if (!product?.id) return;
    
    setLoading(true);
    setError(null);
    
    try {
      // Build query parameters
      const params = new URLSearchParams();
      
      // Add vendor filter if checkbox is checked and vendor is selected
      if (filterByVendor && selectedVendor) {
        params.append('vendor_id', selectedVendor.contact_id);
      }
      
      console.log(`Fetching purchases for product ${product.id}`, params.toString());
      
      const response = await axios.get(
        `${backendUrl}/api/products/${product.id}/purchases?${params.toString()}`
      );
      
      if (response.data.success) {
        setPurchases(response.data.purchases || []);
      } else {
        throw new Error('Failed to fetch purchase data');
      }
    } catch (err) {
      console.error('Error fetching product purchases:', err);
      setError(err.response?.data?.error || err.message || 'Failed to fetch purchase history');
      setPurchases([]);
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
    return purchases.reduce((sum, purchase) => {
      const qty = parseFloat(purchase.quantity) || 0;
      return sum + qty;
    }, 0);
  };

  const getTotalCost = () => {
    return purchases.reduce((sum, purchase) => {
      const total = parseFloat(purchase.total) || 0;
      return sum + total;
    }, 0);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-3xl max-h-[80vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b bg-gradient-to-r from-orange-50 to-red-50">
          <div>
            <div className="flex items-center gap-2">
              <TrendingDown className="w-5 h-5 text-orange-600" />
              <h2 className="text-lg font-semibold">Purchase History</h2>
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
              {selectedVendor && (
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={filterByVendor}
                    onChange={(e) => setFilterByVendor(e.target.checked)}
                    className="w-4 h-4 text-orange-600 rounded focus:ring-orange-500"
                  />
                  <span className="text-sm text-gray-700 flex items-center gap-1">
                    <User className="w-4 h-4" />
                    Show only: <span className="font-medium">{selectedVendor.contact_name || selectedVendor.company_name}</span>
                  </span>
                </label>
              )}
              {!selectedVendor && (
                <span className="text-sm text-gray-500 flex items-center gap-1">
                  <Users className="w-4 h-4" />
                  Showing all vendors
                </span>
              )}
            </div>
            
            <button
              onClick={fetchProductPurchases}
              className="text-orange-600 hover:text-orange-700 flex items-center gap-1 text-sm"
            >
              <RefreshCw className="w-3 h-3" />
              Refresh
            </button>
          </div>
        </div>

        {/* Summary Stats */}
        {!loading && !error && purchases.length > 0 && (
          <div className="grid grid-cols-2 gap-4 p-4 bg-gray-50">
            <div className="bg-white p-3 rounded-lg border">
              <p className="text-xs text-gray-600">Total Quantity Purchased</p>
              <p className="text-xl font-bold text-gray-900">{getTotalQuantity()} units</p>
            </div>
            <div className="bg-white p-3 rounded-lg border">
              <p className="text-xs text-gray-600">Total Cost</p>
              <p className="text-xl font-bold text-gray-900">{formatCurrency(getTotalCost())}</p>
            </div>
          </div>
        )}

        {/* Content */}
        <div className="overflow-y-auto" style={{ maxHeight: 'calc(80vh - 240px)' }}>
          {loading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-orange-600"></div>
              <p className="mt-3 text-gray-600">Loading purchase history...</p>
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center py-12 px-4">
              <div className="text-red-500 text-center">
                <p className="font-medium">Error loading purchases</p>
                <p className="text-sm mt-1">{error}</p>
              </div>
              <button
                onClick={fetchProductPurchases}
                className="mt-4 px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 flex items-center gap-2"
              >
                <RefreshCw className="w-4 h-4" />
                Retry
              </button>
            </div>
          ) : purchases.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 px-4">
              <Package className="w-12 h-12 text-gray-400 mb-3" />
              <p className="text-gray-600 text-center">
                No purchases found for this product
                {filterByVendor && selectedVendor && (
                  <span className="block text-sm mt-1">
                    Try unchecking the vendor filter to see all purchases
                  </span>
                )}
              </p>
            </div>
          ) : (
            <div className="divide-y divide-gray-200">
              {/* Table Header - Desktop */}
              <div className="hidden md:grid md:grid-cols-6 gap-4 px-4 py-3 bg-gray-50 text-sm font-medium text-gray-700">
                <div className="col-span-2">Vendor</div>
                <div>Date</div>
                <div className="text-center">Quantity</div>
                <div className="text-right">Unit Price</div>
                <div className="text-right">Bill</div>
              </div>

              {/* Purchase Rows */}
              {purchases.map((purchase, index) => (
                <div key={`${purchase.bill_id}-${index}`} className="hover:bg-gray-50 transition-colors">
                  {/* Desktop View */}
                  <div className="hidden md:grid md:grid-cols-6 gap-4 px-4 py-3 items-center">
                    <div className="col-span-2 text-gray-800">
                      {purchase.vendor_name}
                    </div>
                    <div className="text-gray-600 text-sm">
                      {formatDate(purchase.date)}
                    </div>
                    <div className="text-center font-medium">
                      {formatQuantity(purchase.quantity, purchase.unit)}
                    </div>
                    <div className="text-right font-medium">
                      {formatCurrency(purchase.rate)}
                    </div>
                    <div className="text-right">
                      <span className="text-sm text-orange-600 hover:text-orange-700">
                        {purchase.bill_number}
                      </span>
                    </div>
                  </div>

                  {/* Mobile View */}
                  <div className="md:hidden px-4 py-3">
                    <div className="flex justify-between items-start mb-2">
                      <div>
                        <div className="font-medium text-gray-800">
                          {purchase.vendor_name}
                        </div>
                        <div className="text-xs text-gray-500 mt-1">
                          {formatDate(purchase.date)}
                        </div>
                      </div>
                      <span className="text-sm text-orange-600">
                        {purchase.bill_number}
                      </span>
                    </div>
                    <div className="flex justify-between items-end">
                      <div className="text-sm text-gray-600">
                        Quantity: <span className="font-medium">{formatQuantity(purchase.quantity, purchase.unit)}</span>
                      </div>
                      <div className="text-sm font-medium">
                        {formatCurrency(purchase.total)}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        {purchases.length > 0 && (
          <div className="p-4 border-t bg-gray-50">
            <div className="text-sm text-gray-600">
              Showing {purchases.length} purchase{purchases.length !== 1 ? 's' : ''} 
              {filterByVendor && selectedVendor ? 
                ` from ${selectedVendor.contact_name || selectedVendor.company_name}` : 
                ' from all vendors'}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ProductPurchaseHistory;
import React from 'react'
import { Package, ShoppingCart, Menu } from 'lucide-react'

export default function IconTest() {
  return (
    <div style={{ padding: '20px', background: 'white' }}>
      <h1>Icon Test</h1>
      <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
        <div>
          <p>Package Icon:</p>
          <Package size={24} color="black" />
        </div>
        <div>
          <p>ShoppingCart Icon:</p>
          <ShoppingCart size={24} color="black" />
        </div>
        <div>
          <p>Menu Icon:</p>
          <Menu size={24} color="black" />
        </div>
      </div>
      <div style={{ marginTop: '20px' }}>
        <p>Direct SVG test:</p>
        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="9" width="18" height="13" rx="2" ry="2"></rect>
          <path d="M12 3v6"></path>
        </svg>
      </div>
    </div>
  )
}
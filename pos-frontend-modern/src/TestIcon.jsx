import React from 'react'
import { Package } from 'lucide-react'

export default function TestIcon() {
  return (
    <div>
      <h1>Icon Test</h1>
      <Package size={24} />
      <Package className="h-6 w-6" />
    </div>
  )
}
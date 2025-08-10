import React, { useMemo, useState, useEffect } from "react";
import { Menu, Search, ShoppingCart, Plus, Minus, Trash2, Sun, Moon, CreditCard, RefreshCcw, X } from "lucide-react";

/**
 * Loyverse‑Style POS (Responsive, Mock Frontend)
 * Stack: React + Tailwind CSS (pure frontend, no backend)
 *
 * Notes for integration later:
 * - This component is intentionally "API-ready":
 *   Replace the mock ITEMS array with a fetch to your catalog (Zoho).
 *   Wire the handleCharge() with your order-create endpoint.
 * - Tailwind classes control layout & responsiveness.
 * - On tablets/desktop (md+), shows split view (Products | Cart)
 *   On mobile, shows a bottom tab bar (Products / Cart) with counts.
 * - Includes search, category filter, quantity controls, VAT (15%),
 *   and a clear/new-sale action.
 */

const CATEGORIES = [
  "All",
  "Beverages",
  "Snacks",
  "Bakery",
  "Dairy",
  "Frozen",
  "Produce",
  "Household",
];

const ITEMS = [
  { id: "bev-1", name: "Americano", price: 8.0, category: "Beverages", emoji: "☕️" },
  { id: "bev-2", name: "Caffè Latte", price: 10.0, category: "Beverages", emoji: "🥤" },
  { id: "bev-3", name: "Bottled Water", price: 3.0, category: "Beverages", emoji: "💧" },
  { id: "snk-1", name: "Potato Chips", price: 6.0, category: "Snacks", emoji: "🥔" },
  { id: "snk-2", name: "Chocolate Bar", price: 5.0, category: "Snacks", emoji: "🍫" },
  { id: "snk-3", name: "Mixed Nuts", price: 12.0, category: "Snacks", emoji: "🥜" },
  { id: "bky-1", name: "Croissant", price: 7.0, category: "Bakery", emoji: "🥐" },
  { id: "bky-2", name: "Blueberry Muffin", price: 9.0, category: "Bakery", emoji: "🫐" },
  { id: "dry-1", name: "Greek Yogurt", price: 8.5, category: "Dairy", emoji: "🥛" },
  { id: "dry-2", name: "Cheddar Cheese", price: 14.0, category: "Dairy", emoji: "🧀" },
  { id: "frz-1", name: "French Fries (1kg)", price: 16.0, category: "Frozen", emoji: "🍟" },
  { id: "prd-1", name: "Bananas (1kg)", price: 8.0, category: "Produce", emoji: "🍌" },
  { id: "prd-2", name: "Apples (1kg)", price: 10.0, category: "Produce", emoji: "🍎" },
  { id: "hhd-1", name: "Paper Towels", price: 11.0, category: "Household", emoji: "🧻" },
  { id: "hhd-2", name: "Dish Soap", price: 9.0, category: "Household", emoji: "🧼" },
  { id: "prd-3", name: "Tomatoes (1kg)", price: 7.0, category: "Produce", emoji: "🍅" },
];

const TAX_RATE = 0.15; // KSA VAT
const CURRENCY = "SAR";

function formatCurrency(n) {
  return new Intl.NumberFormat("en-SA", { style: "currency", currency: CURRENCY }).format(n);
}

export default function POSApp() {
  const [dark, setDark] = useState(false);
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("All");
  const [activeTab, setActiveTab] = useState("products"); // mobile only: 'products' | 'cart'
  const [cart, setCart] = useState([]); // {id, name, price, qty}
  const [viewMode, setViewMode] = useState("grid");

  // THEME: persist + apply to <html> so Tailwind dark: classes work reliably
  // Ensure tailwind.config.js has:  darkMode: 'class'
  useEffect(() => {
    try {
      const saved = localStorage.getItem("theme");
      if (saved === "dark") setDark(true);
      else if (saved === "light") setDark(false);
      else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        setDark(true);
      }
    } catch {}
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    if (dark) root.classList.add("dark"); else root.classList.remove("dark");
    try { localStorage.setItem("theme", dark ? "dark" : "light"); } catch {}
  }, [dark]);

  const filteredItems = useMemo(() => {
    const term = search.trim().toLowerCase();
    return ITEMS.filter((it) =>
      (category === "All" || it.category === category) &&
      (term === "" || it.name.toLowerCase().includes(term))
    );
  }, [search, category]);

  const subtotal = useMemo(() => cart.reduce((sum, line) => sum + line.price * line.qty, 0), [cart]);
  const subtotalQty = useMemo(() => cart.reduce((sum, line) => sum + line.qty, 0), [cart]);
  const tax = useMemo(() => +(subtotal * TAX_RATE).toFixed(2), [subtotal]);
  const total = useMemo(() => +(subtotal + tax).toFixed(2), [subtotal, tax]);

  function addToCart(item) {
    setCart((prev) => {
      const idx = prev.findIndex((l) => l.id === item.id);
      if (idx >= 0) {
        const copy = [...prev];
        copy[idx] = { ...copy[idx], qty: copy[idx].qty + 1 };
        return copy;
      }
      return [...prev, { id: item.id, name: item.name, price: item.price, qty: 1 }];
    });
  }

  function inc(id) {
    setCart((prev) => prev.map((l) => (l.id === id ? { ...l, qty: l.qty + 1 } : l)));
  }

  function dec(id) {
    setCart((prev) => prev
      .map((l) => (l.id === id ? { ...l, qty: Math.max(1, l.qty - 1) } : l))
      .filter((l) => l.qty > 0)
    );
  }

  function removeLine(id) {
    setCart((prev) => prev.filter((l) => l.id !== id));
  }

  function newSale() {
    if (cart.length === 0) return;
    if (confirm("Start a new sale? This will clear the current cart.")) setCart([]);
  }

  function handleCharge() {
    if (cart.length === 0) return alert("Cart is empty");
    // For now, just demo a receipt payload (ready for Zoho order creation later)
    const payload = {
      items: cart.map((l) => ({ id: l.id, name: l.name, price: l.price, qty: l.qty })),
      subtotal,
      tax,
      total,
      currency: CURRENCY,
      timestamp: new Date().toISOString(),
    };
    alert("✅ Payment flow stub.\n\n" + JSON.stringify(payload, null, 2));
    // Later: call your backend (server or edge function) to create Zoho invoice/sales order.
  }

  return (
    <div className="min-h-screen w-full"> 
      <div className="bg-gray-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 min-h-screen flex flex-col">
        {/* Top Bar */}
        <header className="sticky top-0 z-30 w-full border-b border-slate-200/60 dark:border-slate-800 bg-white/80 dark:bg-slate-900/80 backdrop-blur">
          <div className="max-w-7xl mx-auto px-3 py-2 flex items-center gap-2">
            <button className="p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800" aria-label="Menu">
              <Menu className="w-5 h-5" />
            </button>
            <h1 className="font-semibold tracking-tight text-xl md:text-2xl">POS</h1>

            {/* Search */}
            <div className="flex-1" />
            <div className="hidden md:flex items-center gap-2 w-[420px]">
              <div className="relative flex-1">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search items…"
                  className="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-100 dark:bg-slate-800 outline-none focus:ring-2 ring-emerald-500"
                />
              </div>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-1 md:gap-2">
              {/* View toggle */}
              <div className="hidden md:inline-flex rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                <button onClick={() => setViewMode("grid")} className={"px-3 py-2 text-sm " + (viewMode === "grid" ? "bg-emerald-600 text-white" : "hover:bg-slate-100 dark:hover:bg-slate-800")} aria-label="Grid view">
                  <GridIcon />
                </button>
                <button onClick={() => setViewMode("list")} className={"px-3 py-2 text-sm " + (viewMode === "list" ? "bg-emerald-600 text-white" : "hover:bg-slate-100 dark:hover:bg-slate-800")} aria-label="List view">
                  <ListIcon />
                </button>
              </div>
              <button onClick={() => setViewMode(viewMode === "grid" ? "list" : "grid")} className="md:hidden p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800" aria-label="Toggle list/grid">
                {viewMode === "grid" ? <ListIcon /> : <GridIcon />}
              </button>
              <button
                onClick={() => setDark((d) => !d)}
                className="p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800"
                aria-label="Toggle theme"
              >
                {dark ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
              </button>
              <button
                onClick={newSale}
                className="hidden md:inline-flex items-center gap-2 px-3 py-2 rounded-xl bg-slate-900 text-white dark:bg-white dark:text-slate-900 hover:opacity-90"
              >
                <RefreshCcw className="w-4 h-4" /> New Sale
              </button>
              <button
                onClick={() => setActiveTab("cart")}
                className="inline-flex md:hidden items-center gap-2 px-3 py-2 rounded-xl bg-emerald-600 text-white"
              >
                <ShoppingCart className="w-4 h-4" />
                <span>{subtotalQty}</span>
              </button>
            </div>
          </div>

          {/* Mobile search */}
          <div className="md:hidden px-3 pb-3">
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search items…"
                className="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-100 dark:bg-slate-800 outline-none focus:ring-2 ring-emerald-500"
              />
            </div>
          </div>

          {/* Category chips */}
          <div className="px-3 pb-2">
            <div className="max-w-7xl mx-auto overflow-x-auto scrollbar-none">
              <div className="flex gap-2 pb-2">
                {CATEGORIES.map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setCategory(cat)}
                    className={
                      "px-3 py-1.5 rounded-full border text-sm whitespace-nowrap transition " +
                      (category === cat
                        ? "bg-emerald-600 text-white border-emerald-600"
                        : "border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800")
                    }
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </header>

        {/* Main content */}
        <div className="max-w-7xl mx-auto w-full flex-1 px-3 md:px-4 py-3 md:py-4 grid md:grid-cols-12 gap-3 md:gap-4">
          {/* Products Panel */}
          <section className={
            "md:col-span-8 " + (activeTab === "products" ? "block" : "hidden md:block")
          }>
            {viewMode === "grid" ? (
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3">
                {filteredItems.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => addToCart(item)}
                    className="group rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-3 hover:border-emerald-500 hover:shadow-sm transition active:scale-[0.98] text-left"
                  >
                    <div className="aspect-[4/3] w-full rounded-xl bg-emerald-50 dark:bg-emerald-900/20 grid place-items-center text-4xl">
                      <span className="select-none">{item.emoji}</span>
                    </div>
                    <div className="mt-2 flex items-start justify-between gap-2">
                      <div>
                        <p className="font-medium leading-tight line-clamp-2">{item.name}</p>
                        <p className="text-xs text-slate-500">{item.category}</p>
                      </div>
                      <p className="font-semibold text-emerald-700 dark:text-emerald-400">{formatCurrency(item.price)}</p>
                    </div>
                    <div className="mt-2 hidden sm:flex items-center gap-1 text-emerald-700 dark:text-emerald-400">
                      <Plus className="w-4 h-4" /> <span className="text-xs">Add</span>
                    </div>
                  </button>
                ))}
                {filteredItems.length === 0 && (
                  <div className="col-span-full py-16 text-center text-slate-500">
                    <p className="text-sm">No items match your search/filter.</p>
                  </div>
                )}
              </div>
            ) : (
              <div className="space-y-2">
                {filteredItems.map((item) => (
                  <div key={item.id} className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-3 flex items-center gap-3">
                    <div className="w-14 h-14 rounded-xl bg-emerald-50 dark:bg-emerald-900/20 grid place-items-center text-2xl select-none">{item.emoji}</div>
                    <div className="flex-1 min-w-0">
                      <p className="font-medium truncate">{item.name}</p>
                      <p className="text-xs text-slate-500">{item.category}</p>
                    </div>
                    <div className="text-right">
                      <p className="font-semibold text-emerald-700 dark:text-emerald-400">{formatCurrency(item.price)}</p>
                      <button onClick={() => addToCart(item)} className="mt-1 inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 hover:opacity-90">
                        <Plus className="w-4 h-4" /> <span className="text-sm">Add</span>
                      </button>
                    </div>
                  </div>
                ))}
                {filteredItems.length === 0 && (
                  <div className="py-16 text-center text-slate-500">
                    <p className="text-sm">No items match your search/filter.</p>
                  </div>
                )}
              </div>
            )}
          </section>

          {/* Cart Panel */}
          <aside className={
            "md:col-span-4 " + (activeTab === "cart" ? "block" : "hidden md:block")
          }>
            <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-3 md:p-4 flex flex-col h-[calc(100dvh-15rem)] md:h-[calc(100dvh-12rem)]">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold">Current Ticket</h2>
                <button onClick={newSale} className="text-sm inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-slate-100 dark:bg-slate-800 hover:opacity-90">
                  <RefreshCcw className="w-4 h-4" /> New
                </button>
              </div>

              <div className="mt-2 space-y-2 overflow-auto pr-1 flex-1">
                {cart.map((line) => (
                  <div key={line.id} className="rounded-xl border border-slate-200 dark:border-slate-800 p-2">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 min-w-0">
                        <p className="font-medium truncate">{line.name}</p>
                        <p className="text-xs text-slate-500">{formatCurrency(line.price)} each</p>
                      </div>
                      <div className="flex items-center gap-1">
                        <button onClick={() => dec(line.id)} className="p-1.5 rounded-lg bg-slate-100 dark:bg-slate-800">
                          <Minus className="w-4 h-4" />
                        </button>
                        <span className="w-8 text-center font-semibold">{line.qty}</span>
                        <button onClick={() => inc(line.id)} className="p-1.5 rounded-lg bg-slate-100 dark:bg-slate-800">
                          <Plus className="w-4 h-4" />
                        </button>
                      </div>
                      <p className="w-20 text-right font-semibold">{formatCurrency(line.qty * line.price)}</p>
                      <button onClick={() => removeLine(line.id)} className="p-1.5 rounded-lg text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))}
                {cart.length === 0 && (
                  <div className="py-12 text-center text-slate-500">
                    <ShoppingCart className="w-6 h-6 mx-auto mb-2" />
                    <p className="text-sm">Your ticket is empty. Add items from the left.</p>
                  </div>
                )}
              </div>

              {/* Totals */}
              <div className="mt-3 border-t border-slate-200 dark:border-slate-800 pt-3 space-y-1 text-sm">
                <div className="flex justify-between"><span>Subtotal ({subtotalQty} items)</span><span>{formatCurrency(subtotal)}</span></div>
                <div className="flex justify-between"><span>VAT (15%)</span><span>{formatCurrency(tax)}</span></div>
                <div className="flex justify-between text-base font-semibold"><span>Total</span><span>{formatCurrency(total)}</span></div>
              </div>

              {/* Actions */}
              <div className="mt-3 grid grid-cols-2 gap-2">
                <button
                  onClick={handleCharge}
                  className="col-span-2 md:col-span-1 inline-flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-emerald-600 text-white hover:bg-emerald-700"
                >
                  <CreditCard className="w-5 h-5" /> Charge
                </button>
                <button
                  onClick={newSale}
                  className="inline-flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-slate-900 text-white dark:bg-white dark:text-slate-900 hover:opacity-90"
                >
                  <RefreshCcw className="w-5 h-5" /> New Sale
                </button>
              </div>
            </div>
          </aside>
        </div>

        {/* Mobile bottom nav */}
        <nav className="md:hidden sticky bottom-0 z-30 bg-white/80 dark:bg-slate-900/80 backdrop-blur border-t border-slate-200/60 dark:border-slate-800">
          <div className="grid grid-cols-2">
            <button
              onClick={() => setActiveTab("products")}
              className={
                "flex items-center justify-center gap-2 py-3 font-medium " +
                (activeTab === "products" ? "text-emerald-600" : "text-slate-600 dark:text-slate-300")
              }
            >
              <GridIcon /> Products
            </button>
            <button
              onClick={() => setActiveTab("cart")}
              className={
                "flex items-center justify-center gap-2 py-3 font-medium " +
                (activeTab === "cart" ? "text-emerald-600" : "text-slate-600 dark:text-slate-300")
              }
            >
              <ShoppingCart className="w-5 h-5" /> Cart
              {subtotalQty > 0 && (
                <span className="inline-flex items-center justify-center text-xs font-semibold min-w-5 h-5 px-1 rounded-full bg-emerald-600 text-white">{subtotalQty}</span>
              )}
            </button>
          </div>
        </nav>
      </div>
    </div>
  );
}

function GridIcon() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="w-5 h-5">
      <path d="M3 3h8v8H3V3zm0 10h8v8H3v-8zm10-10h8v8h-8V3zm0 10h8v8h-8v-8z" />
    </svg>
  );
}

function ListIcon() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="w-5 h-5">
      <path d="M4 6h16v2H4V6zm0 5h16v2H4v-2zm0 5h16v2H4v-2z" />
    </svg>
  );
}

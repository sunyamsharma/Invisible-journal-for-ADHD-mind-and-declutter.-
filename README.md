# The Invisible Journal — Shopify Business Page

A ready-to-use, self-contained landing page for **The Invisible Journal** — a
guided notebook for the ADHD mind and decluttering. No frameworks, no build
step, no external files: everything (HTML + CSS) lives in `index.html`.

## How to use it on Shopify

You have two easy options.

### Option A — Paste it as a Shopify Page (fastest)
1. In Shopify Admin, go to **Online Store → Pages → Add page**.
2. Give it a title (e.g. *The Invisible Journal*).
3. In the content editor toolbar, click the **`< >` (Show HTML)** button.
4. Open `index.html`, copy everything **inside** the `<body>` tag, and paste it in.
5. Copy the contents of the `<style>` block (in `<head>`) into your theme, or
   keep the inline styles — they're scoped enough to drop straight in.
6. **Save**, then set it as a navigation link or your homepage.

### Option B — Use it as a standalone landing page
Just open `index.html` in a browser, or host it anywhere (Shopify assets,
Netlify, GitHub Pages, etc.). It's fully responsive and works on its own.

## What to customize
- **Buy buttons:** the "Add to cart" link (`href="#"`) → point it at your real
  Shopify product URL, or replace with a Shopify product/buy button block.
- **Price:** currently `$34` (was `$44`) in the product section.
- **Copy & testimonials:** placeholder names/quotes — swap in real reviews.
- **Colors:** edit the CSS variables at the top of the `<style>` block
  (`--sage`, `--clay`, `--cream`, etc.).
- **Product image:** the gradient "book" block is a placeholder — replace the
  `.product-visual` div with an `<img>` of your journal.

## Design notes
Warm, calming, low-stimulation palette (sage + clay + cream) chosen to be
gentle on ADHD readers — clear hierarchy, generous spacing, and no cluttered
spreads. Sections: hero, empathy, what-it-is, how-it-works, product/buy,
testimonials, FAQ, and a closing call-to-action.

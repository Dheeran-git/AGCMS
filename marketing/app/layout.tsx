import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

const SITE_URL = process.env.AGCMS_SITE_URL ?? "https://agcms.com";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: "AGCMS — AI Governance & Compliance Monitoring",
  description:
    "Cryptographically signed, legally defensible audit trails across a multi-tenant live AI enforcement plane.",
  icons: { icon: "/favicon.ico" },
  alternates: {
    types: {
      "application/rss+xml": [
        { url: "/changelog/rss.xml", title: "AGCMS Changelog" },
      ],
    },
  },
};

const NAV = [
  { href: "/product", label: "Product" },
  { href: "/compliance", label: "Compliance" },
  { href: "/pricing", label: "Pricing" },
  { href: "/security", label: "Security" },
  { href: "https://uip-f4b0bbe5.mintlify.app", label: "Docs", external: true },
  { href: "https://github.com/Dheeran-git/AGCMS", label: "GitHub", external: true },
  { href: "/status", label: "Status" },
  { href: "/changelog", label: "Changelog" },
] as const;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen flex flex-col">
        <header className="border-b border-border">
          <div className="mx-auto max-w-6xl px-6 h-14 flex items-center justify-between">
            <Link href="/" className="font-semibold tracking-tight">
              AGCMS
            </Link>
            <nav className="flex items-center gap-6 text-sm text-fg-muted">
              {NAV.map((n) =>
                "external" in n && n.external ? (
                  <a
                    key={n.href}
                    href={n.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="hover:text-fg-primary"
                  >
                    {n.label}
                  </a>
                ) : (
                  <Link key={n.href} href={n.href} className="hover:text-fg-primary">
                    {n.label}
                  </Link>
                ),
              )}
              <Link
                href="/book-demo"
                className="bg-accent hover:bg-accent-bright text-white text-sm px-3 py-1.5 rounded-md"
              >
                Book demo
              </Link>
            </nav>
          </div>
        </header>

        <main className="flex-1">{children}</main>

        <footer className="border-t border-border mt-16">
          <div className="mx-auto max-w-6xl px-6 py-8 text-sm text-fg-subtle flex justify-between">
            <span>© {new Date().getFullYear()} AGCMS. All rights reserved.</span>
            <div className="flex gap-4">
              <Link href="/security" className="hover:text-fg-primary">Trust</Link>
              <Link href="/legal/privacy" className="hover:text-fg-primary">Privacy</Link>
              <Link href="/legal/terms" className="hover:text-fg-primary">Terms</Link>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}

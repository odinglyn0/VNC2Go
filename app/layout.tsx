import type { Metadata, Viewport } from "next"
import { Geist_Mono, Inter } from "next/font/google"
import localFont from "next/font/local"

import "./globals.css"
import { ThemeProvider } from "@/components/theme-provider"
import { Toaster } from "@/components/ui/sonner"
import { cn } from "@/lib/utils"

const inter = Inter({ subsets: ["latin"], variable: "--font-sans" })

const fontMono = Geist_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
})

const coolvetica = localFont({
  src: "./fonts/coolvetica.woff",
  variable: "--font-coolvetica",
  display: "swap",
})

export const metadata: Metadata = {
  title: {
    default: "VNC2Go",
    template: "%s · VNC2Go",
  },
  description:
    "Connect to any VNC server straight from your browser.",
  applicationName: "VNC2Go",
  metadataBase: new URL("https://vnc2go.odinglynn.com"),
  alternates: { canonical: "/" },
  keywords: [
    "VNC",
    "browser VNC client",
    "noVNC",
    "remote desktop",
    "encrypted VNC",
    "zero log VNC",
    "RFB",
  ],
  authors: [{ name: "VNC2Go" }],
  category: "technology",
  robots: {
    index: true,
    follow: true,
    googleBot: { index: true, follow: true, "max-image-preview": "large" },
  },
  openGraph: {
    type: "website",
    siteName: "VNC2Go",
    title: "VNC2Go — Browser VNC client, end-to-end encrypted, zero logs",
    description:
      "Connect to any VNC server straight from your browser.",
    url: "https://vnc2go.odinglynn.com",
    locale: "en_IE",
  },
  twitter: {
    card: "summary_large_image",
    title: "VNC2Go — Browser VNC client",
    description:
      "Connect to any VNC server straight from your browser.",
  },
  icons: {
    icon: "/favicon.ico",
  },
}

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#0a0a0a" },
  ],
  colorScheme: "dark light",
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={cn(
        "antialiased",
        fontMono.variable,
        "font-sans",
        inter.variable,
        coolvetica.variable,
      )}
    >
      <body>
        <ThemeProvider>
          {children}
          <Toaster richColors position="top-center" />
        </ThemeProvider>
      </body>
    </html>
  )
}

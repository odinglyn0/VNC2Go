import type { Metadata } from "next"
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
  title: "VNC2Go",
  description: "Connect to any VNC server straight from your browser.",
  metadataBase: new URL("https://vnc2go.odinglynn.com"),
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

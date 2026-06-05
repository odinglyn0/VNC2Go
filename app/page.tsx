import type { Metadata } from "next"

import { VncSearch } from "@/components/vnc-search"

export const metadata: Metadata = {
  title: "Connect to any VNC server from your browser",
}

const jsonLd = {
  "@context": "https://schema.org",
  "@type": "WebApplication",
  name: "VNC2Go",
  url: "https://vnc2go.odinglynn.com",
  applicationCategory: "UtilitiesApplication",
  operatingSystem: "Any",
  description:
    "Connect to any VNC server straight from your browser.",
  offers: {
    "@type": "Offer",
    price: "0",
    priceCurrency: "EUR",
  },
  featureList: [
    "Browser-based VNC client",
    "End-to-end encryption",
    "Zero data retention",
    "Private proxy mode",
  ],
}

export default function Page() {
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
      <VncSearch />
    </>
  )
}

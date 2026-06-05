import type { MetadataRoute } from "next"

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: "*",
        allow: "/",
        disallow: ["/api/"],
      },
    ],
    sitemap: "https://vnc2go.odinglynn.com/sitemap.xml",
    host: "https://vnc2go.odinglynn.com",
  }
}

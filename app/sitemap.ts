import type { MetadataRoute } from "next"

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url: "https://vnc2go.odinglynn.com",
      changeFrequency: "monthly",
      priority: 1,
    },
  ]
}

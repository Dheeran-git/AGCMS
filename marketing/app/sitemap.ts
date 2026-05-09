import type { MetadataRoute } from "next";

const SITE_URL = process.env.AGCMS_SITE_URL ?? "https://agcms.com";

const ROUTES: { path: string; priority: number; changeFrequency: MetadataRoute.Sitemap[number]["changeFrequency"] }[] = [
  { path: "/",          priority: 1.0, changeFrequency: "weekly"  },
  { path: "/product",   priority: 0.9, changeFrequency: "monthly" },
  { path: "/compliance",priority: 0.9, changeFrequency: "monthly" },
  { path: "/pricing",   priority: 0.9, changeFrequency: "monthly" },
  { path: "/security",  priority: 0.8, changeFrequency: "monthly" },
  { path: "/status",    priority: 0.6, changeFrequency: "daily"   },
  { path: "/changelog", priority: 0.7, changeFrequency: "weekly"  },
  { path: "/blog",      priority: 0.5, changeFrequency: "monthly" },
  { path: "/book-demo", priority: 0.7, changeFrequency: "yearly"  },
  { path: "/signup",    priority: 0.7, changeFrequency: "yearly"  },
  { path: "/legal/privacy", priority: 0.3, changeFrequency: "yearly" },
  { path: "/legal/terms",   priority: 0.3, changeFrequency: "yearly" },
];

export default function sitemap(): MetadataRoute.Sitemap {
  const lastModified = new Date();
  return ROUTES.map((r) => ({
    url: `${SITE_URL}${r.path}`,
    lastModified,
    changeFrequency: r.changeFrequency,
    priority: r.priority,
  }));
}

"""Third-party platform tenancy.

A host that resolves onto a shared SaaS/hosting platform — a ``*.wordpress.com``
blog, a ``*.netlify.app`` site, a ``*.github.io`` page, a hosted Discourse forum —
is a *customer of that platform*, not the target's own infrastructure. Even when
it sits under the target's apex (a CNAME to the platform), the platform owns the
box, the patching, and most of the surface. Flagging it as a top target wastes an
operator's time and, on a bug-bounty program, is usually out of scope.

These helpers detect platform tenancy from the hostname itself and from a resolved
CNAME, so scoring and the Analyst can down-rank and label them.
"""

from __future__ import annotations

# Suffixes that are shared hosting/SaaS platforms. A host *ending in* one of these
# (or whose CNAME does) is a tenant on that platform, not first-party infra.
PLATFORM_SUFFIXES: dict[str, str] = {
    "wordpress.com": "WordPress.com",
    "wpengine.com": "WP Engine",
    "netlify.app": "Netlify",
    "netlify.com": "Netlify",
    "vercel.app": "Vercel",
    "github.io": "GitHub Pages",
    "gitlab.io": "GitLab Pages",
    "pages.dev": "Cloudflare Pages",
    "herokuapp.com": "Heroku",
    "readthedocs.io": "Read the Docs",
    "gitbook.io": "GitBook",
    "notion.site": "Notion",
    "webflow.io": "Webflow",
    "myshopify.com": "Shopify",
    "squarespace.com": "Squarespace",
    "wixsite.com": "Wix",
    "zendesk.com": "Zendesk",
    "helpscoutdocs.com": "Help Scout",
    "statuspage.io": "Statuspage",
    "discourse.group": "Discourse",
    "discourse-cdn.com": "Discourse",
    "ghost.io": "Ghost",
    "substack.com": "Substack",
    "medium.com": "Medium",
    "surge.sh": "Surge",
    "firebaseapp.com": "Firebase Hosting",
    "web.app": "Firebase Hosting",
    "azurewebsites.net": "Azure App Service",
    "cloudfront.net": "AWS CloudFront",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
}


def _match_suffix(host: str) -> str | None:
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return None
    for suffix, name in PLATFORM_SUFFIXES.items():
        if host == suffix or host.endswith("." + suffix):
            return name
    return None


def platform_tenant(host: str, cname: str | None = None) -> str | None:
    """Return the platform name if ``host`` (or its CNAME) is a tenant on a shared
    hosting platform, else None. A CNAME onto the platform is the strong signal —
    it's how a vanity subdomain (blog.example.com) points at wordpress.com."""
    return _match_suffix(cname) or _match_suffix(host)

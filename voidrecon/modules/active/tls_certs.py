"""Live TLS certificate harvesting.

Certificate transparency is passive and lags; pulling the certificate straight
off a live host reveals the Subject Alternative Names it serves *right now* —
often internal or sibling hostnames that never hit a public CT log. For each
in-scope, resolving host this module completes a TLS handshake, reads the leaf
certificate, and extracts its SANs, issuer, and validity window.

Active and scope-gated. Requires the ``cryptography`` package (bundled in the
``full`` extra); skips cleanly if it's absent.
"""

from __future__ import annotations

import asyncio
import ssl

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence
from voidrecon.core.module import Module, Phase, register
from voidrecon.utils import net

try:
    from cryptography import x509

    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    _HAS_CRYPTO = False


@register
class TlsCerts(Module):
    name = "tls_certs"
    phase = Phase.ACTIVE
    active = True
    description = "Harvest hostnames from live TLS certificate SANs"
    depends_on = ("dns_resolve",)

    async def run(self, ctx: RunContext) -> None:
        if not _HAS_CRYPTO:
            self.log.info("cryptography not installed — skipping (pip install cryptography)")
            return
        targets = [
            a for a in ctx.store.assets(kind=AssetKind.SUBDOMAIN) + ctx.store.assets(kind=AssetKind.DOMAIN)
            if a.attrs.get("resolved_ips") and ctx.can_touch(a.value)
        ]
        if not targets:
            self.log.info("no in-scope resolving hosts for TLS harvesting")
            return
        sem = asyncio.Semaphore(min(int(ctx.config.get("opsec.max_concurrency", 20)), 30))
        new_hosts = 0

        async def worker(asset):
            nonlocal new_hosts
            async with sem:
                new_hosts += await self._grab(ctx, asset)

        await asyncio.gather(*(worker(a) for a in targets))
        self.log.info("TLS harvest over %d hosts; +%d SAN hostnames", len(targets), new_hosts)

    async def _grab(self, ctx: RunContext, asset) -> int:
        host = asset.value
        loop = asyncio.get_event_loop()
        try:
            pem = await asyncio.wait_for(
                loop.run_in_executor(None, self._fetch_cert, host), timeout=10.0)
        except Exception:
            return 0
        if not pem:
            return 0
        try:
            cert = x509.load_pem_x509_certificate(pem.encode())
        except Exception:
            return 0
        sans: list[str] = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            pass
        asset.attrs["tls_sans"] = sorted(set(sans))[:100]
        try:
            asset.attrs["tls_issuer"] = cert.issuer.rfc4514_string()
            asset.attrs["tls_not_after"] = cert.not_valid_after_utc.isoformat()
        except Exception:
            pass
        added = 0
        for san in sans:
            san = net.normalize_host(san.lstrip("*."))
            if not net.is_domain(san):
                continue
            related = ctx.scope.is_related(san)
            kind = AssetKind.SUBDOMAIN if related else AssetKind.DOMAIN
            a = ctx.add_asset(kind, san, source=self.name, confidence=Confidence.LIKELY, via="tls_san")
            if a:
                a.tags.add("tls-san")
                if related:
                    added += 1
        return added

    def _fetch_cert(self, host: str) -> str | None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with ctx.wrap_socket(_connect(host, 443), server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
            return ssl.DER_cert_to_PEM_cert(der) if der else None
        except Exception:
            return None


def _connect(host: str, port: int):
    import socket

    return socket.create_connection((host, port), timeout=8.0)

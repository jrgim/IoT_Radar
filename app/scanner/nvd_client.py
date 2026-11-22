import logging
import time

import nvdlib

logger = logging.getLogger(__name__)

_FREE_TIER_SLEEP = 0.6
_CACHE_TTL_SECS = 24 * 3600
CVE_MIN_YEAR = 2015
_cache: dict[str, tuple[float, list[dict]]] = {}


def search_cves(product: str, version: str = "", api_key: str = "") -> list[dict]:
    if not product:
        return []

    keyword = f"{product} {version}".strip()

    cached = _cache.get(keyword)
    if cached is not None:
        ts, cves = cached
        if time.time() - ts < _CACHE_TTL_SECS:
            return cves

    kwargs: dict = {"keywordSearch": keyword, "limit": 20}
    if api_key:
        kwargs["key"] = api_key

    results = []
    try:
        results = nvdlib.searchCVE(**kwargs)
    except Exception as exc:
        logger.warning("NVD fallo para '%s': %s", keyword, exc)
        return []
    finally:
        if not api_key:
            time.sleep(_FREE_TIER_SLEEP)

    cves: list[dict] = []
    for r in results:
        score = _extract_score(r)
        if score is None or score < 7.0:
            continue
        if _cve_year(r.id) < CVE_MIN_YEAR:
            continue
        cves.append(
            {
                "cve_id": r.id,
                "cvss_score": score,
                "description": _extract_description(r),
            }
        )

    cves.sort(key=lambda x: x["cvss_score"], reverse=True)
    _cache[keyword] = (time.time(), cves)
    return cves


def _cve_year(cve_id: str) -> int:
    try:
        return int(cve_id.split("-")[1])
    except (IndexError, ValueError):
        return 0


def _extract_score(r) -> float | None:
    for attr in ("v31score", "v30score", "v2score"):
        val = getattr(r, attr, None)
        if val is not None:
            try:
                return float(val)
            except (TypeError, ValueError):
                continue
    return None


def _extract_description(r) -> str:
    try:
        for desc in r.descriptions:
            if desc.lang == "en":
                return desc.value
    except Exception:
        pass
    return ""

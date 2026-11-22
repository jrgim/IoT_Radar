import time
from unittest.mock import MagicMock, patch

import pytest
import scanner.nvd_client as nvd


@pytest.fixture(autouse=True)
def clear_cache():
    nvd._cache.clear()
    yield
    nvd._cache.clear()


def _make_cve(cve_id, v31score=None, v30score=None, v2score=None, year=None, desc="A vulnerability."):
    r = MagicMock()
    r.id = cve_id
    r.v31score = v31score
    r.v30score = v30score
    r.v2score = v2score
    desc_obj = MagicMock()
    desc_obj.lang = "en"
    desc_obj.value = desc
    r.descriptions = [desc_obj]
    return r



class TestSearchCVEs:
    def test_empty_product_returns_empty(self):
        assert nvd.search_cves("") == []

    def test_returns_cves_above_score_threshold(self):
        cve = _make_cve("CVE-2020-1234", v31score=7.5)
        with patch("nvdlib.searchCVE", return_value=[cve]):
            results = nvd.search_cves("openssh", "8.0")
        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2020-1234"

    def test_filters_out_low_cvss_score(self):
        cve = _make_cve("CVE-2020-1234", v31score=5.0)
        with patch("nvdlib.searchCVE", return_value=[cve]):
            results = nvd.search_cves("openssh", "8.0")
        assert results == []

    def test_filters_out_old_cves(self):
        cve = _make_cve("CVE-2014-9999", v31score=9.8)
        with patch("nvdlib.searchCVE", return_value=[cve]):
            results = nvd.search_cves("product", "1.0")
        assert results == []

    def test_accepts_cves_from_2015(self):
        cve = _make_cve("CVE-2015-0001", v31score=7.0)
        with patch("nvdlib.searchCVE", return_value=[cve]):
            results = nvd.search_cves("product", "1.0")
        assert len(results) == 1

    def test_sorted_by_cvss_desc(self):
        cves = [
            _make_cve("CVE-2020-0001", v31score=7.5),
            _make_cve("CVE-2020-0002", v31score=9.8),
            _make_cve("CVE-2020-0003", v31score=8.1),
        ]
        with patch("nvdlib.searchCVE", return_value=cves):
            results = nvd.search_cves("product", "1.0")
        scores = [r["cvss_score"] for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_results_cached_second_call_skips_nvdlib(self):
        cve = _make_cve("CVE-2020-1234", v31score=7.5)
        with patch("nvdlib.searchCVE", return_value=[cve]) as mock_nvd:
            nvd.search_cves("openssh", "8.0")
            nvd.search_cves("openssh", "8.0")
        assert mock_nvd.call_count == 1

    def test_cache_expires_after_ttl(self):
        cve = _make_cve("CVE-2020-1234", v31score=7.5)
        with patch("nvdlib.searchCVE", return_value=[cve]) as mock_nvd:
            nvd.search_cves("openssh", "8.0")
            # Expire the cache
            nvd._cache["openssh 8.0"] = (time.time() - nvd._CACHE_TTL_SECS - 1, [])
            nvd.search_cves("openssh", "8.0")
        assert mock_nvd.call_count == 2

    def test_nvdlib_exception_returns_empty(self):
        with patch("nvdlib.searchCVE", side_effect=Exception("network error")):
            results = nvd.search_cves("product", "1.0")
        assert results == []

    def test_product_only_no_version(self):
        cve = _make_cve("CVE-2020-1234", v31score=7.5)
        with patch("nvdlib.searchCVE", return_value=[cve]) as mock_nvd:
            nvd.search_cves("apache")
        call_kwargs = mock_nvd.call_args[1]
        assert call_kwargs["keywordSearch"] == "apache"

    def test_api_key_passed_to_nvdlib(self):
        with patch("nvdlib.searchCVE", return_value=[]) as mock_nvd:
            nvd.search_cves("product", "1.0", api_key="my_key")
        assert mock_nvd.call_args[1].get("key") == "my_key"

    def test_no_api_key_not_passed(self):
        with patch("nvdlib.searchCVE", return_value=[]) as mock_nvd:
            nvd.search_cves("product", "1.0")
        assert "key" not in mock_nvd.call_args[1]



class TestCVEYear:
    def test_parses_year_correctly(self):
        assert nvd._cve_year("CVE-2023-12345") == 2023

    def test_parses_2015(self):
        assert nvd._cve_year("CVE-2015-0001") == 2015

    def test_invalid_format_returns_zero(self):
        assert nvd._cve_year("INVALID") == 0

    def test_non_numeric_year_returns_zero(self):
        assert nvd._cve_year("CVE-ABCD-1234") == 0



class TestExtractScore:
    def test_prefers_v31_score(self):
        r = _make_cve("CVE-2020-1", v31score=9.8, v30score=7.5, v2score=6.0)
        assert nvd._extract_score(r) == 9.8

    def test_falls_back_to_v30_when_no_v31(self):
        r = _make_cve("CVE-2020-1", v31score=None, v30score=7.5, v2score=6.0)
        assert nvd._extract_score(r) == 7.5

    def test_falls_back_to_v2_when_no_v31_or_v30(self):
        r = _make_cve("CVE-2020-1", v31score=None, v30score=None, v2score=6.0)
        assert nvd._extract_score(r) == 6.0

    def test_returns_none_when_no_scores(self):
        r = _make_cve("CVE-2020-1", v31score=None, v30score=None, v2score=None)
        assert nvd._extract_score(r) is None



class TestExtractDescription:
    def test_extracts_english_description(self):
        r = MagicMock()
        en_desc = MagicMock(lang="en", value="English desc")
        es_desc = MagicMock(lang="es", value="Spanish desc")
        r.descriptions = [es_desc, en_desc]
        assert nvd._extract_description(r) == "English desc"

    def test_returns_empty_when_no_english(self):
        r = MagicMock()
        r.descriptions = [MagicMock(lang="es", value="Solo español")]
        assert nvd._extract_description(r) == ""

    def test_returns_empty_on_exception(self):
        r = MagicMock()
        r.descriptions = MagicMock(side_effect=Exception("error"))
        assert nvd._extract_description(r) == ""

import pytest
from backend.core.whitelist import (
    normalize_domain,
    load_whitelist,
    is_whitelisted,
    determine_scope,
    check_whitelist_hit,
)
from typing import Set


class TestNormalizeDomain:
    """Test cases for normalize_domain function."""

    def test_normalize_basic_domain(self):
        """Test basic domain normalization."""
        assert normalize_domain("example.com") == "example.com"
        assert normalize_domain("Example.COM") == "example.com"
        assert normalize_domain(" example.com ") == "example.com"

    def test_normalize_with_www(self):
        """Test domain with www prefix."""
        assert normalize_domain("www.example.com") == "example.com"

    def test_normalize_with_trailing_dot(self):
        """Test domain with trailing dot."""
        assert normalize_domain("example.com.") == "example.com"

    def test_normalize_with_both(self):
        """Test domain with www and trailing dot."""
        assert normalize_domain("www.example.com.") == "example.com"

    def test_normalize_empty_and_invalid(self):
        """Test with empty or invalid domains."""
        assert normalize_domain("") == ""
        assert normalize_domain("...") == ".."
        assert normalize_domain("...com") == "...com"


class TestLoadWhitelist:
    """Test cases for load_whitelist function."""

    def test_load_whitelist_existing_file(self, tmp_path):
        """Test loading whitelist from an existing file."""
        whitelist_file = tmp_path / "whitelist.txt"
        whitelist_file.write_text("example.com\nanother.example.com\n")

        wl_set = load_whitelist(str(whitelist_file))

        assert "example.com" in wl_set
        assert "another.example.com" in wl_set
        assert "invalid.com" not in wl_set

    def test_load_whitelist_empty_file(self, tmp_path):
        """Test loading empty whitelist file."""
        whitelist_file = tmp_path / "empty_whitelist.txt"
        whitelist_file.write_text("")

        wl_set = load_whitelist(str(whitelist_file))
        assert wl_set == set()

    def test_load_whitelist_nonexistent_file(self):
        """Test loading from nonexistent file returns empty set."""
        wl_set = load_whitelist("nonexistent/path/whitelist.txt")
        assert wl_set == set()

    def test_load_whitelist_with_comments_and_whitespace(self, tmp_path):
        """Test loading whitelist with whitespace and empty lines."""
        whitelist_file = tmp_path / "whitelist.txt"
        whitelist_file.write_text("\n example.com\n\n another.example.com \n\t\n")

        wl_set = load_whitelist(str(whitelist_file))

        assert wl_set == {"example.com", "another.example.com"}


class TestIsWhitelisted:
    """Test cases for is_whitelisted function."""

    def test_is_whitelisted_exact_match(self):
        """Test exact match whitelist checking."""
        wl = {"example.com", "google.com"}
        assert is_whitelisted("example.com", wl) is True
        assert is_whitelisted("google.com", wl) is True
        assert is_whitelisted("facebook.com", wl) is False

    def test_is_whitelisted_case_insensitive(self):
        """Test case insensitive matching."""
        wl = {"example.com"}
        assert is_whitelisted("Example.COM", wl) is True
        assert is_whitelisted("examPLE.com", wl) is True

    def test_is_whitelisted_with_normalization(self):
        """Test with www and trailing dot normalization."""
        wl = {"example.com"}
        assert is_whitelisted("www.example.com", wl) is True
        assert is_whitelisted("example.com.", wl) is True


class TestDetermineScope:
    """Test cases for determine_scope function."""

    def test_determine_scope_exact(self):
        """Test exact scope when domains match."""
        assert determine_scope("example.com", "example.com") == "exact"

    def test_determine_scope_apex(self):
        """Test apex scope when query is subdomain of whitelisted."""
        # sub.example.com (3 parts) vs example.com (2 parts)
        assert determine_scope("sub.example.com", "example.com") == "apex"
        # mail.sub.example.com (4 parts) vs sub.example.com (3 parts)
        assert determine_scope("mail.sub.example.com", "sub.example.com") == "apex"

    def test_determine_scope_subdomain(self):
        """Test subdomain scope when whitelisted is subdomain of query."""
        # example.com (2 parts) vs sub.example.com (3 parts)
        assert determine_scope("example.com", "sub.example.com") == "subdomain"
        # sub.example.com (3 parts) vs mail.sub.example.com (4 parts)
        assert determine_scope("sub.example.com", "mail.sub.example.com") == "subdomain"


class TestCheckWhitelistHit:
    """Test cases for check_whitelist_hit function."""

    def test_check_whitelist_hit_exact_match(self):
        """Test whitelist hit with exact match."""
        wl = {"example.com"}
        hits = check_whitelist_hit("example.com", wl)
        assert hits is not None
        assert len(hits) == 1
        assert hits[0].matched_domain == "example.com"
        assert hits[0].scope == "exact"
        assert hits[0].reason == "manual-whitelist"

    def test_check_whitelist_hit_apex_match(self):
        """Test whitelist hit with apex match."""
        wl = {"example.com"}
        hits = check_whitelist_hit("sub.example.com", wl)
        assert hits is not None
        assert len(hits) == 1
        assert hits[0].matched_domain == "example.com"
        assert hits[0].scope == "apex"
        assert hits[0].reason == "manual-whitelist"

    def test_check_whitelist_hit_subdomain_match(self):
        """Test whitelist hit with subdomain match."""
        wl = {"mail.example.com"}
        hits = check_whitelist_hit("example.com", wl)
        assert hits is not None
        assert len(hits) == 1
        assert hits[0].matched_domain == "mail.example.com"
        assert hits[0].scope == "subdomain"
        assert hits[0].reason == "manual-whitelist"

    def test_check_whitelist_hit_no_match(self):
        """Test no whitelist hit when domain not whitelisted."""
        wl = {"example.com"}
        hits = check_whitelist_hit("notexample.com", wl)
        assert hits is None

    def test_check_whitelist_hit_multiple_matches(self):
        """Test multiple hits when domain matches multiple whitelisted domains."""
        wl = {"example.com", "sub.example.com"}
        hits = check_whitelist_hit("sub.example.com", wl)
        assert hits is not None
        # Should match both
        matched_domains = {hit.matched_domain for hit in hits}
        assert matched_domains == {"example.com", "sub.example.com"}

    def test_check_whitelist_hit_empty_domain(self):
        """Test with empty domain."""
        wl = {"example.com"}
        hits = check_whitelist_hit("", wl)
        assert hits is None

    def test_check_whitelist_hit_custom_reason(self):
        """Test with custom reason."""
        wl = {"example.com"}
        hits = check_whitelist_hit("example.com", wl, reason="custom-whitelist")
        assert hits is not None
        assert len(hits) == 1
        assert hits[0].reason == "custom-whitelist"

    def test_check_whitelist_hit_normalization(self):
        """Test that domain normalization works in check_whitelist_hit."""
        wl = {"example.com"}
        hits = check_whitelist_hit("Sub.Example.COM.", wl)
        assert hits is not None
        assert hits[0].matched_domain == "example.com"
        assert hits[0].scope == "apex"

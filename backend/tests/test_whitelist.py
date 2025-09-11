import pytest
from backend.core.whitelist import (
    normalize_domain,
    load_whitelist,
    is_whitelisted,
    validate_domain,
    matches_wildcard,
    find_wildcard_matches,
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

    def test_determine_scope_wildcard_subdomain(self):
        """Test wildcard subdomain scope."""
        assert (
            determine_scope("mail.example.com", "*.example.com") == "wildcard-subdomain"
        )

    def test_determine_scope_wildcard_tld(self):
        """Test wildcard TLD scope."""
        assert determine_scope("mail.google.com", "mail.google.*") == "wildcard-tld"

    def test_determine_scope_wildcard_pattern(self):
        """Test wildcard pattern scope."""
        assert determine_scope("verysafe.com", "*safe*") == "wildcard-pattern"


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

    def test_check_whitelist_hit_wildcard_subdomain_match(self):
        """Test whitelist hit with wildcard subdomain match."""
        wl = {"*.example.com"}
        hits = check_whitelist_hit("mail.example.com", wl)
        assert hits is not None
        assert len(hits) == 1
        assert hits[0].matched_domain == "*.example.com"
        assert hits[0].scope == "wildcard-subdomain"
        assert hits[0].reason == "manual-whitelist"

    def test_check_whitelist_hit_wildcard_tld_match(self):
        """Test whitelist hit with wildcard TLD match."""
        wl = {"mail.google.*"}
        hits = check_whitelist_hit("mail.google.com", wl)
        assert hits is not None
        assert len(hits) == 1
        assert hits[0].matched_domain == "mail.google.*"
        assert hits[0].scope == "wildcard-tld"
        assert hits[0].reason == "manual-whitelist"

    def test_check_whitelist_hit_wildcard_pattern_match(self):
        """Test whitelist hit with wildcard pattern match."""
        wl = {"*secure*"}
        hits = check_whitelist_hit("verysecure.com", wl)
        assert hits is not None
        assert len(hits) == 1
        assert hits[0].matched_domain == "*secure*"
        assert hits[0].scope == "wildcard-pattern"
        assert hits[0].reason == "manual-whitelist"

    def test_check_whitelist_hit_invalid_domain(self):
        """Test with invalid domain."""
        wl = {"example.com"}
        hits = check_whitelist_hit("invalid..domain", wl)
        assert hits is None

    def test_check_whitelist_hit_mixed_regular_and_wildcard(self):
        """Test whitelist hit with both regular and wildcard matches."""
        wl = {"example.com", "*.example.com", "*secure*"}
        hits = check_whitelist_hit("mail.example.com", wl)
        assert hits is not None
        # Should match both example.com (apex) and *.example.com (wildcard-subdomain)
        scopes = {hit.scope for hit in hits}
        assert "apex" in scopes
        assert "wildcard-subdomain" in scopes


class TestValidateDomain:
    """Test cases for validate_domain function."""

    def test_validate_domain_basic(self):
        """Test basic domain validation."""
        assert validate_domain("example.com") is True
        assert validate_domain("sub.example.com") is True
        assert validate_domain("deep.sub.example.com") is True

    def test_validate_domain_with_hyphens(self):
        """Test domain with hyphens."""
        assert validate_domain("my-example.com") is True
        assert validate_domain("sub.my-example.com") is True

    def test_validate_domain_ipv4(self):
        """Test IPv4 address validation."""
        assert validate_domain("192.168.1.1") is True
        assert validate_domain("127.0.0.1") is True

    def test_validate_domain_ipv6(self):
        """Test IPv6 address validation."""
        assert validate_domain("[::1]") is True
        assert validate_domain("[2001:db8::1]") is True

    def test_validate_domain_idna(self):
        """Test IDNA domain validation."""
        assert validate_domain("москва.рф") is True
        assert validate_domain("xn--nxasmq6b") is True

    def test_validate_domain_invalid_length(self):
        """Test domain with invalid length."""
        assert validate_domain("") is False
        assert validate_domain("a" * 254) is False

    def test_validate_domain_invalid_format(self):
        """Test domain with invalid format."""
        assert validate_domain("example..com") is False
        assert validate_domain("-example.com") is False
        assert validate_domain("example-.com") is False
        assert validate_domain("example.com-") is False

    def test_validate_domain_invalid_chars(self):
        """Test domain with invalid characters."""
        assert validate_domain("example_.com") is False
        assert validate_domain("exa_mple.com") is False


class TestMatchesWildcard:
    """Test cases for matches_wildcard function."""

    def test_matches_wildcard_subdomain_pattern(self):
        """Test wildcard matching for subdomain pattern."""
        assert matches_wildcard("mail.example.com", "*.example.com") is True
        assert matches_wildcard("sub.mail.example.com", "*.example.com") is True
        assert matches_wildcard("example.com", "*.example.com") is False

    def test_matches_wildcard_tld_pattern(self):
        """Test wildcard matching for TLD pattern."""
        assert matches_wildcard("mail.google.com", "mail.google.*") is True
        assert matches_wildcard("mail.google.org", "mail.google.*") is True
        assert matches_wildcard("mail.yahoo.com", "mail.google.*") is False

    def test_matches_wildcard_contains_pattern(self):
        """Test wildcard matching for contains pattern."""
        assert matches_wildcard("verysafe.com", "*safe*") is True
        assert matches_wildcard("unsafe.com", "*safe*") is True
        assert matches_wildcard("danger.com", "*safe*") is False

    def test_matches_wildcard_multiple_wildcards(self):
        """Test wildcard matching with multiple wildcards."""
        assert matches_wildcard("a.b.c.example.com", "*.b.*.com") is True
        assert matches_wildcard("a.x.c.example.com", "*.b.*.com") is False

    def test_matches_wildcard_edge_cases(self):
        """Test wildcard matching edge cases."""
        assert matches_wildcard("", "*") is False
        assert matches_wildcard("example.com", "") is False
        assert matches_wildcard("example.com", "*") is True


class TestFindWildcardMatches:
    """Test cases for find_wildcard_matches function."""

    def test_find_wildcard_matches_subdomain(self):
        """Test finding wildcard matches for subdomain."""
        wl = {"*.example.com", "test.com"}
        matches = find_wildcard_matches("mail.example.com", wl)
        assert len(matches) == 1
        assert matches[0] == ("*.example.com", "wildcard-subdomain")

    def test_find_wildcard_matches_multiple_patterns(self):
        """Test finding matches for multiple wildcard patterns."""
        wl = {"*.example.com", "*test*", "mail.*"}
        matches = find_wildcard_matches("mail.example.com", wl)
        assert len(matches) == 2
        pattern_scopes = set(matches)
        assert ("*.example.com", "wildcard-subdomain") in pattern_scopes
        assert ("mail.*", "wildcard-tld") in pattern_scopes

    def test_find_wildcard_matches_no_match(self):
        """Test no wildcard matches found."""
        wl = {"*.google.com"}
        matches = find_wildcard_matches("example.com", wl)
        assert matches == []

    def test_find_wildcard_matches_regular_apex(self):
        """Test finding wildcard matches for apex subdomain."""
        wl = {"*.example.com"}
        matches = find_wildcard_matches("example.com", wl)
        assert len(matches) == 1
        assert matches[0] == ("*.example.com", "wildcard-apex")

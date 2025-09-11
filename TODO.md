# TODO: Phishing Detection Features

This document tracks the implementation status of features in the phishing detection system.

### Core Modules

### Ingestion

- [x] Implement `parse_eml.py` - Advanced email parsing (headers, subject, body, MIME structures)
- [x] Implement `mime.py` - MIME type handling and parsing
- [x] Implement `models.py` - Data models for email processing structures
- [x] Implement `auth_parser.py` - Authentication header parsing (SPF, DKIM, DMARC)
- [x] Implement `body_cleaner.py` - Email body content normalization and cleaning
- [x] Implement `headers.py` - Header processing and validation utilities
- [x] Implement `addresses.py` - Email address parsing and validation
- [x] Implement `sender_identity.py` - Sender identity analysis and verification
- [x] Implement `metrics.py` - Analysis metrics and statistics calculation
- [x] Implement `error_policy.py` - Error handling policies and fallback mechanisms
- [x] Implement `attachment_analysis.py` - Advanced attachment analysis with MIME sniffing, macro detection, and security scanning
- [ ] Add advanced attachment extraction with security scanning (upgrading beyond current implementation)
- [ ] Enhance encoding handling for international email support

### Whitelist

- [x] Implement `whitelist.py` - Basic O(1) domain membership with simple normalization
- [ ] Improve `whitelist.py` - Add subdomain support, wildcard matching, better domain validation

### Keywords

- [x] Implement `keywords.py` - Basic token scan with hardcoded keywords
- [ ] Improve `keywords.py` - Make keywords configurable, add weights, better regex patterns, context awareness

### Score

- [x] Implement `score.py` - Basic weighted aggregation for risk scoring
- [ ] Improve `score.py` - Add more sophisticated scoring algorithms, confidence levels, detailed explanations

### Position Analysis

- [x] Implement `position.py` - subject/early-body weighting with configurable multipliers and decay functions
- [x] Add logic to prioritize suspicious content in email subject and early body text
- [x] Integrate position weighting into scoring system with comprehensive statistics

### Edit Distance

- [x] Implement `edit_distance.py` - banded Levenshtein with cutoff and comprehensive detection patterns
- [x] Add fuzzy matching for known phishing domains/brands (with brand database and custom domains)
- [x] Optimize for performance with cutoff thresholds and evidence generation

### URL Checks

- [x] Implement `url_checks.py` - href/text mismatch, IP literals, shorteners, punycode
- [x] Detect URL text/href discrepancies
- [x] Identify IP addresses in URLs
- [x] Handle URL shorteners
- [x] Check for punycode/IDN homograph attacks

### Reply-To vs From Mismatch

- [ ] Implement `replyto_from.py` - Reply-To vs From mismatch rules
- [ ] Compare Reply-To and From headers for inconsistencies
- [ ] Flag suspicious mismatches

### Attachment Heuristics

- [ ] Implement `attachments.py` - attachment heuristics (ext, double-ext, macros)
- [ ] Check file extensions for suspicious patterns
- [ ] Detect double extensions (e.g., .pdf.exe)
- [ ] Identify macro-enabled documents

### Unicode/Confusables

- [ ] Implement `confusables.py` - unicode skeleton + IDN homograph checks
- [ ] Normalize unicode characters for comparison
- [ ] Detect homograph attacks using similar-looking characters
- [ ] Check IDN domains for suspicious patterns

### Authentication Checks

- [x] Implement `auth_parser.py` - Authentication header parsing and validation
- [x] Parse Authentication-Results headers
- [x] Parse Received-SPF headers
- [ ] Implement `dkim_verify.py` (OPTIONAL) - live DKIM verification using dkimpy + DNS
- [ ] Implement `spf_check.py` (OPTIONAL) - simplified SPF check via DNS TXT
- [ ] Implement `dmarc_check.py` (OPTIONAL) - DMARC policy & alignment via DNS TXT

### Explain Module

- [ ] Implement `explain.py` - human-readable reasons
- [ ] Generate detailed explanations for phishing scores
- [ ] Provide actionable feedback for flagged emails

## Utils Modules

### Text Processing

- [ ] Implement `text.py` - text processing utilities
- [ ] Add text normalization functions
- [ ] Implement tokenization and cleaning

### Domain Handling

- [ ] Implement `domains.py` - domain processing utilities
- [ ] Add domain parsing and validation
- [ ] Implement domain reputation checks

### HTML Processing

- [ ] Implement `html.py` - HTML parsing utilities
- [ ] Extract links and content from HTML
- [ ] Sanitize and analyze HTML structure

### DNS Cache

- [ ] Implement `dns_cache.py` - DNS caching for performance
- [ ] Cache DNS lookups for repeated queries
- [ ] Handle DNS timeout and error cases

## UI Module

### Web Interface

- [x] Implement `main.py` - Streamlit frontend application launcher
- [x] Implement `app.py` - Main Streamlit application logic and routing
- [x] Implement `config.py` - Application configuration and settings
- [x] Implement `api_client.py` - Backend API client for communication
- [x] Implement `file_uploader.py` - Secure file upload component
- [x] Implement `file_validator.py` - File validation and security checks
- [x] Implement `analysis_results.py` - Analysis results display component
- [x] Implement `email_display.py` - Email content viewer
- [x] Implement `components.py` - Reusable UI components
- [x] Implement `sidebar.py` - Application sidebar and navigation
- [ ] Add advanced visualization for analysis metrics
- [ ] Implement batch processing for multiple emails
- [ ] Add export functionality for analysis reports

## Data Files

### Whitelist

- [x] `whitelist.txt` - Basic domain whitelist
- [ ] Expand `whitelist.txt` - Add more domains, categorize by trust levels

### Suspicious Terms

- [ ] Create `data/suspicious_terms.txt`
- [ ] Populate with common phishing keywords
- [ ] Maintain and update term list

### Known Brands

- [ ] Create `data/known_brands.txt`
- [ ] List legitimate brand names and domains
- [ ] Use for brand impersonation detection

## Testing

### Existing Tests

- [x] Implement `test_api.py` - API endpoint tests
- [x] Implement `test_core.py` - Core module (keywords, whitelist, score) tests
- [x] Implement `test_addresses.py` - Email address processing tests
- [x] Implement `test_auth_parser.py` - Authentication header parsing tests
- [x] Implement `test_body_cleaner.py` - Email body cleaning tests
- [x] Implement `test_body.py` - Email body processing tests
- [x] Implement `test_cid.py` - CID content processing tests
- [x] Implement `test_headers.py` - Email header processing tests
- [x] Implement `test_sender_identity.py` - Sender identity analysis tests
- [x] Implement `test_sender_identity_integration.py` - Sender identity integration tests
- [x] Implement `test_mime_metrics.py` - MIME metrics calculation tests
- [x] Implement `test_inline_images.py` - Inline image processing tests
- [x] Implement `test_attachments.py` - Email attachment processing tests
- [x] Implement `test_reader.py` - Email reader functionality tests
- [x] Implement `test_fixtures.py` - Test fixture utilities tests
- [x] Implement `test_attachment_analysis.py` - Advanced attachment analysis tests with security patterns
- [x] Implement `test_edit_distance.py` - Comprehensive edit distance and lookalike detection tests
- [x] Implement `test_mime_metrics.py` - MIME metrics calculation tests
- [ ] Implement `test_ingestion.py` - Complete ingestion pipeline tests
- [ ] Implement `test_position.py` - Position analysis unit tests
- [ ] Improve test coverage - Add edge cases, performance tests, fuzz testing
- [ ] Add property-based testing with hypothesis

### Unit Tests

- [ ] Implement `test_position.py` - Position analysis (subject/early-body) tests
- [x] Implement `test_edit_distance.py` - Fuzzy matching and edit distance tests (comprehensive implementation with 200+ test cases)
- [ ] Implement `test_url_checks.py` - URL validation and security tests
- [ ] Implement `test_replyto_from.py` - Reply-To/From header mismatch tests
- [ ] Implement `test_confusables.py` - Unicode confusable character tests
- [ ] Implement `test_explain.py` - Explanation module tests
- [ ] Implement `test_text.py` - Text processing utility tests
- [ ] Implement `test_domains.py` - Domain processing tests
- [ ] Implement `test_html.py` - HTML parsing and analysis tests
- [ ] Implement `test_dns_cache.py` - DNS caching tests
- [ ] Implement `test_ui.py` - Frontend UI component tests

### Integration Tests

- [ ] Add comprehensive integration tests
- [ ] Test end-to-end email analysis pipeline
- [ ] Validate scoring accuracy

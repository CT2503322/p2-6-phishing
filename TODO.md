# TODO: Phishing Detection Features

This document tracks the implementation status of features in the phishing detection system.

### Core Modules

### Ingestion

- [x] Implement `parse_eml.py` - Basic email parsing (headers, subject, body)
- [ ] Improve `parse_eml.py` - Add low-level MIME multipart parsing, attachment extraction, encoding handling

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

- [ ] Implement `position.py` - subject/early-body weighting
- [ ] Add logic to prioritize suspicious content in email subject and early body text
- [ ] Integrate position weighting into scoring system

### Edit Distance

- [ ] Implement `edit_distance.py` - banded Levenshtein with cutoff
- [ ] Add fuzzy matching for known phishing domains/brands
- [ ] Optimize for performance with cutoff thresholds

### URL Checks

- [ ] Implement `url_checks.py` - href/text mismatch, IP literals, shorteners, punycode
- [ ] Detect URL text/href discrepancies
- [ ] Identify IP addresses in URLs
- [ ] Handle URL shorteners
- [ ] Check for punycode/IDN homograph attacks

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

- [ ] Create `auth_checks/` directory
- [ ] Implement `auth_headers.py` - parse Authentication-Results, Received-SPF
- [ ] Implement `dkim_verify.py` (OPTIONAL) - live DKIM verify using dkimpy + DNS
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

- [x] Implement `main.py` - Streamlit frontend application
- [x] Create web interface for email analysis
- [x] Add file upload functionality
- [x] Display analysis results and explanations

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

- [x] Implement `test_api.py` - Basic API tests
- [x] Implement `test_core.py` - Basic core module tests
- [x] Implement `test_ingestion.py` - Basic ingestion tests
- [ ] Improve test coverage - Add edge cases, integration tests, performance tests

### Unit Tests

- [ ] Implement `test_position.py`
- [ ] Implement `test_edit_distance.py`
- [ ] Implement `test_url_checks.py`
- [ ] Implement `test_replyto_from.py`
- [ ] Implement `test_attachments.py`
- [ ] Implement `test_confusables.py`
- [ ] Implement `test_auth_headers.py`
- [ ] Implement `test_explain.py`
- [ ] Implement `test_text.py`
- [ ] Implement `test_domains.py`
- [ ] Implement `test_html.py`
- [ ] Implement `test_dns_cache.py`
- [ ] Implement `test_ui.py`

### Integration Tests

- [ ] Add comprehensive integration tests
- [ ] Test end-to-end email analysis pipeline
- [ ] Validate scoring accuracy

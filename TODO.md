# TODO: Phishing Detection Features

This document tracks the implementation status of features in the phishing detection system.

### Core Modules

### Ingestion

- [x] Implement `parse_eml.py` - Basic email parsing (headers, subject, body)
- [x] Improve `parse_eml.py` - Add low-level MIME multipart parsing, attachment extraction, encoding handling
- [x] Implement `clean_html.py` - HTML content cleaning utilities
- [x] Implement `clean_zerowidth.py` - Zero-width character removal

### Domain Whitelist

- [x] Implement domain whitelisting - Basic domain membership checks
- [ ] Improve domain whitelisting - Add subdomain support, wildcard matching, better validation

### Keyword Detection

- [x] Implement keyword detection - Token scan with suspicious keywords
- [ ] Improve keyword detection - Make keywords configurable, add weights, context awareness

### Advanced Checks

- [x] Implement `url_checks.py` - URL analysis and validation (href/text mismatch, IP literals, shorteners, punycode)
- [x] Implement `attachment_checks.py` - Attachment heuristic validation
- [x] Implement `identity_checks.py` - Sender identity verification
- [x] Implement `routing_checks.py` - Email routing validation
- [x] Implement `lexical_score.py` - Lexical analysis scoring
- [x] Implement `scoring.py` - Combined risk scoring algorithm

### Score

- [x] Implement `scoring.py` - Combined risk scoring algorithm
- [ ] Improve scoring algorithm - Add more sophisticated algorithms, confidence levels, detailed explanations

### Machine Learning Detection

- [x] Implement `ml.py` - Machine learning utilities and training pipeline
- [x] Implement ML model training - Naive Bayes Complement/Multinomial, Logistic Regression
- [x] Implement model persistence - Save/load trained models
- [x] Integrate ML prediction into API (/analyze/ml endpoint)
- [ ] Expand ML capabilities - Add more model types (SVM, Random Forest, etc.)
- [ ] Improve ML training - Hyperparameter tuning, cross-validation

### LLM Detection

- [x] Implement `/analyze/llm` endpoint - OpenAI GPT integration for phishing analysis
- [x] Add LLM prompt engineering - Detailed analysis prompts with specific indicators
- [x] Integrate LLM responses into scoring system - Parse JSON responses, map to labels/scores
- [ ] Optimize LLM usage - Caching, batch processing, prompt refinement

### Position Analysis

- [ ] Implement `position.py` - subject/early-body weighting
- [ ] Add logic to prioritize suspicious content in email subject and early body text
- [ ] Integrate position weighting into scoring system

### Edit Distance

- [x] Implement `edit_distance.py` - banded Levenshtein with cutoff
- [x] Add fuzzy matching for known phishing domains/brands
- [x] Optimize for performance with cutoff thresholds

### Reply-To vs From Mismatch

- [ ] Implement `replyto_from.py` - Reply-To vs From mismatch rules
- [ ] Compare Reply-To and From headers for inconsistencies
- [ ] Flag suspicious mismatches

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

- [x] Implement `explain.py` - human-readable reasons
- [ ] Generate detailed explanations for phishing scores
- [ ] Provide actionable feedback for flagged emails

## Utils Modules

### Text Processing

- [x] Implement `text.py` - text processing utilities
- [x] Add text normalization functions
- [x] Implement tokenization and cleaning

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

- [x] Create `data/suspicious_terms.txt`
- [x] Populate with common phishing keywords
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

- [x] Add comprehensive integration tests
- [x] Test end-to-end email analysis pipeline
- [x] Validate scoring accuracy

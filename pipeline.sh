#!/bin/bash

# Agentic Browser Security Pipeline
# Enhanced with configurable wordlist and character controls

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
OUTPUT_DIR="./output"
TEMP_DIR="./temp"
LOG_FILE="./pipeline.log"
RISK_THRESHOLD=50
WORDLIST_MODE="none"
CHARSET_MODE="whitelist"
WORDLIST_FILE=""
CHARSET_FILE=""
STRICT_MODE=false

# Functions
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}ERROR: $1${NC}" | tee -a "$LOG_FILE"
    exit 1
}

warn() {
    echo -e "${YELLOW}WARNING: $1${NC}" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}SUCCESS: $1${NC}" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}INFO: $1${NC}" | tee -a "$LOG_FILE"
}

usage() {
    cat << EOF
Usage: $0 [OPTIONS] <URL>

Enhanced web content processing pipeline with configurable security controls.

OPTIONS:
    -o, --output DIR               Output directory (default: ./output)
    -t, --temp DIR                 Temporary directory (default: ./temp)
    -r, --risk-threshold NUM       Risk threshold (0-100, default: 50)
    
    Word Filtering:
    -w, --wordlist-mode MODE       Word filtering mode: blacklist|whitelist|none (default: none)
    -W, --wordlist-file FILE       Custom wordlist file
    
    Character Filtering:
    -c, --charset-mode MODE        Character filtering mode: blacklist|whitelist|none (default: whitelist)
    -C, --charset-file FILE        Custom character set file
    
    Other Options:
    -s, --strict                   Strict mode - fail on any violations
    -v, --verbose                  Verbose output
    -h, --help                     Show this help message

EXAMPLES:
    # Basic usage with default settings
    $0 https://example.com
    
    # Use word blacklist to filter dangerous phrases
    $0 --wordlist-mode blacklist https://example.com
    
    # Use word whitelist for maximum restriction
    $0 --wordlist-mode whitelist --wordlist-file ./approved-words.txt https://example.com
    
    # Strict mode - fail if any violations detected
    $0 --wordlist-mode blacklist --strict https://suspicious-site.com
    
    # Custom character set
    $0 --charset-file ./extended-charset.txt https://international-site.com

CONFIGURATION FILES:
    Default configuration files are in ./config/:
    - wordlist-blacklist.txt    Dangerous words/phrases to block
    - wordlist-whitelist.txt    Approved words only
    - charset-blacklist.txt     Dangerous characters to block
    - charset-whitelist.txt     Allowed characters only

EOF
}

cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}

# Trap cleanup
trap cleanup EXIT

# Parse arguments
VERBOSE=false
STDIN_MODE=false
URL=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -t|--temp)
            TEMP_DIR="$2"
            shift 2
            ;;
        -r|--risk-threshold)
            RISK_THRESHOLD="$2"
            shift 2
            ;;
        -w|--wordlist-mode)
            WORDLIST_MODE="$2"
            if [[ ! "$WORDLIST_MODE" =~ ^(blacklist|whitelist|none)$ ]]; then
                error "Invalid wordlist mode: $WORDLIST_MODE"
            fi
            shift 2
            ;;
        -W|--wordlist-file)
            WORDLIST_FILE="$2"
            shift 2
            ;;
        -c|--charset-mode)
            CHARSET_MODE="$2"
            if [[ ! "$CHARSET_MODE" =~ ^(blacklist|whitelist|none)$ ]]; then
                error "Invalid charset mode: $CHARSET_MODE"
            fi
            shift 2
            ;;
        -C|--charset-file)
            CHARSET_FILE="$2"
            shift 2
            ;;
        -s|--strict)
            STRICT_MODE=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --stdin)
            STDIN_MODE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            error "Unknown option: $1"
            ;;
        *)
            if [[ -z "$URL" ]]; then
                URL="$1"
            else
                error "Multiple URLs provided"
            fi
            shift
            ;;
    esac
done

# Validate input
if [[ "$STDIN_MODE" == false && -z "$URL" ]]; then
    error "URL required when not using --stdin mode"
fi

if [[ ! "$RISK_THRESHOLD" =~ ^[0-9]+$ ]] || [[ "$RISK_THRESHOLD" -lt 0 ]] || [[ "$RISK_THRESHOLD" -gt 100 ]]; then
    error "Risk threshold must be a number between 0 and 100"
fi

# Create directories
mkdir -p "$OUTPUT_DIR" "$TEMP_DIR"

# Initialize log
log "Starting agentic browser security pipeline"
log "Configuration:"
log "  Output directory: $OUTPUT_DIR"
log "  Risk threshold: $RISK_THRESHOLD"
log "  Wordlist mode: $WORDLIST_MODE"
log "  Charset mode: $CHARSET_MODE"
log "  Strict mode: $STRICT_MODE"

if [[ "$VERBOSE" == true ]]; then
    log "Verbose mode enabled"
fi

# Step 1: Process page
info "Step 1: Processing page (HTML -> Markdown)"
STEP1_OUTPUT="$TEMP_DIR/step1_processed.json"

if [[ "$STDIN_MODE" == true ]]; then
    log "Reading HTML from stdin"
    node process_page.js > "$STEP1_OUTPUT" || error "Step 1 failed"
else
    log "Fetching URL: $URL"
    node process_page.js "$URL" > "$STEP1_OUTPUT" || error "Step 1 failed"
fi

if [[ "$VERBOSE" == true ]]; then
    WORD_COUNT=$(jq -r '.word_count // 0' "$STEP1_OUTPUT" 2>/dev/null || echo "0")
    log "Processed content: $WORD_COUNT words"
fi

success "Step 1 completed"

# Step 2: Clean and sanitize with configurable controls
info "Step 2: Sanitizing content with security controls"
STEP2_OUTPUT="$TEMP_DIR/step2_sanitized.json"

# Build sanitizer command
SANITIZER_CMD="node markdown_clean_script.js"
SANITIZER_CMD="$SANITIZER_CMD --wordlist-mode $WORDLIST_MODE"
SANITIZER_CMD="$SANITIZER_CMD --charset-mode $CHARSET_MODE"

if [[ -n "$WORDLIST_FILE" ]]; then
    SANITIZER_CMD="$SANITIZER_CMD --wordlist-file $WORDLIST_FILE"
fi

if [[ -n "$CHARSET_FILE" ]]; then
    SANITIZER_CMD="$SANITIZER_CMD --charset-file $CHARSET_FILE"
fi

if [[ "$STRICT_MODE" == true ]]; then
    SANITIZER_CMD="$SANITIZER_CMD --strict"
fi

if [[ "$VERBOSE" == true ]]; then
    log "Sanitizer command: $SANITIZER_CMD"
fi

# Run sanitizer
if ! cat "$STEP1_OUTPUT" | $SANITIZER_CMD > "$STEP2_OUTPUT" 2>&1; then
    if [[ "$STRICT_MODE" == true ]]; then
        error "Content failed strict security validation. Check $STEP2_OUTPUT for details."
    else
        error "Step 2 failed"
    fi
fi

# Extract security metrics
RISK_SCORE=$(jq -r '.untrusted_content.security_scan.risk_score // 0' "$STEP2_OUTPUT" 2>/dev/null || echo "0")
CHAR_VIOLATIONS=$(jq -r '.untrusted_content.security_scan.character_violations // 0' "$STEP2_OUTPUT" 2>/dev/null || echo "0")
WORD_VIOLATIONS=$(jq -r '.untrusted_content.security_scan.word_violations // 0' "$STEP2_OUTPUT" 2>/dev/null || echo "0")
INJECTION_ATTEMPTS=$(jq -r '.untrusted_content.security_scan.injection_attempts // 0' "$STEP2_OUTPUT" 2>/dev/null || echo "0")

log "Security scan results:"
log "  Risk score: $RISK_SCORE/100"
log "  Character violations: $CHAR_VIOLATIONS"
log "  Word violations: $WORD_VIOLATIONS"
log "  Injection attempts: $INJECTION_ATTEMPTS"

if [[ "$RISK_SCORE" -gt "$RISK_THRESHOLD" ]]; then
    warn "High risk content detected (score: $RISK_SCORE, threshold: $RISK_THRESHOLD)"
    
    if [[ "$VERBOSE" == true ]]; then
        log "Security violations:"
        jq -r '.untrusted_content.security_scan.violations[] | "  - \(.type): \(.context // .word)"' "$STEP2_OUTPUT" 2>/dev/null | head -10 || log "  Unable to parse violations"
        log "Injection detections:"
        jq -r '.untrusted_content.security_scan.detections[] | "  - \(.type): \(.match)"' "$STEP2_OUTPUT" 2>/dev/null | head -10 || log "  Unable to parse detections"
    fi
fi

success "Step 2 completed"

# Step 3: Generate final output
info "Step 3: Generating final output"

# Create timestamped filename
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
FINAL_OUTPUT="$OUTPUT_DIR/processed_content_${TIMESTAMP}.json"

# Add pipeline metadata
if ! jq --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" \
   --arg url "$URL" \
   --argjson risk_score "$RISK_SCORE" \
   --argjson threshold "$RISK_THRESHOLD" \
   --arg wordlist_mode "$WORDLIST_MODE" \
   --arg charset_mode "$CHARSET_MODE" \
   --argjson strict_mode "$STRICT_MODE" \
   '. + {
     pipeline_metadata: {
       processed_at: $timestamp,
       source_url: $url,
       risk_score: $risk_score,
       risk_threshold: $threshold,
       high_risk: ($risk_score > $threshold),
       security_config: {
         wordlist_mode: $wordlist_mode,
         charset_mode: $charset_mode,
         strict_mode: $strict_mode
       }
     }
   }' "$STEP2_OUTPUT" > "$FINAL_OUTPUT" 2>/dev/null; then
    warn "Unable to add pipeline metadata due to encoding issues. Copying sanitized output as-is."
    cp "$STEP2_OUTPUT" "$FINAL_OUTPUT"
fi

success "Step 3 completed"

# Summary
echo
log "Pipeline completed successfully"
log "Final output: $FINAL_OUTPUT"
log "Content ready for agent processing"

if [[ "$RISK_SCORE" -gt "$RISK_THRESHOLD" ]]; then
    warn "SECURITY NOTICE: Content exceeded risk threshold - review before agent processing"
fi

if [[ "$VERBOSE" == true ]]; then
    info "Content preview:"
    jq -r '.untrusted_content.content' "$FINAL_OUTPUT" 2>/dev/null | head -20 || echo "Unable to preview content"
fi

# Exit with appropriate code
if [[ "$RISK_SCORE" -gt "$RISK_THRESHOLD" ]]; then
    exit 2  # Warning exit code
else
    exit 0
fi
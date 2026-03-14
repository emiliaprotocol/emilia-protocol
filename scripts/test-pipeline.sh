#!/bin/bash
# =============================================================================
# EMILIA Protocol — End-to-End Pipeline Test
# =============================================================================
# This script:
#   1. Registers 3 test sender entities
#   2. Submits receipts from each sender about Rex and Ruby
#   3. Verifies Rex and Ruby's scores change from default 50
#   4. Tests v2 claims-based receipt submission
#   5. Confirms the full pipeline works
#
# IMPORTANT: Hit www.emiliaprotocol.ai (not emiliaprotocol.ai) 
# because Cloudflare redirect strips Authorization headers on POST.
#
# Usage: bash scripts/test-pipeline.sh
# =============================================================================

BASE="https://www.emiliaprotocol.ai"
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
GOLD='\033[0;33m'
NC='\033[0m'

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  EMILIA PROTOCOL — END-TO-END PIPELINE TEST${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""

# -------------------------------------------
# STEP 0: Check current state
# -------------------------------------------
echo -e "${GOLD}[0] Checking current state...${NC}"
REX_BEFORE=$(curl -s "$BASE/api/score/rex-booking-v1")
RUBY_BEFORE=$(curl -s "$BASE/api/score/ruby-retention-v1")

REX_SCORE_BEFORE=$(echo "$REX_BEFORE" | python3 -c "import json,sys; print(json.load(sys.stdin)['emilia_score'])" 2>/dev/null)
REX_RECEIPTS_BEFORE=$(echo "$REX_BEFORE" | python3 -c "import json,sys; print(json.load(sys.stdin)['total_receipts'])" 2>/dev/null)
RUBY_SCORE_BEFORE=$(echo "$RUBY_BEFORE" | python3 -c "import json,sys; print(json.load(sys.stdin)['emilia_score'])" 2>/dev/null)
RUBY_RECEIPTS_BEFORE=$(echo "$RUBY_BEFORE" | python3 -c "import json,sys; print(json.load(sys.stdin)['total_receipts'])" 2>/dev/null)

echo "  Rex:  score=$REX_SCORE_BEFORE, receipts=$REX_RECEIPTS_BEFORE"
echo "  Ruby: score=$RUBY_SCORE_BEFORE, receipts=$RUBY_RECEIPTS_BEFORE"
echo ""

# -------------------------------------------
# STEP 1: Register 3 test sender entities
# -------------------------------------------
echo -e "${GOLD}[1] Registering test sender entities...${NC}"

register_entity() {
  local ID=$1
  local NAME=$2
  local DESC=$3
  local RESULT=$(curl -s -X POST "$BASE/api/entities/register" \
    -H "Content-Type: application/json" \
    -d "{
      \"entity_id\": \"$ID\",
      \"display_name\": \"$NAME\",
      \"entity_type\": \"agent\",
      \"description\": \"$DESC\",
      \"capabilities\": [\"testing\", \"pipeline_verification\"]
    }")
  
  local KEY=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null)
  local ERR=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)
  
  if [ -n "$KEY" ] && [ "$KEY" != "" ]; then
    echo -e "  ${GREEN}✓${NC} Registered $ID → key: ${KEY:0:20}..."
    echo "$KEY"
  elif echo "$ERR" | grep -q "already registered"; then
    echo -e "  ${GOLD}⚠${NC} $ID already exists — need its API key"
    echo "ALREADY_EXISTS"
  else
    echo -e "  ${RED}✗${NC} Failed: $ERR"
    echo "FAILED"
  fi
}

KEY1=$(register_entity "ep-test-sender-1" "Test Sender Alpha" "Pipeline test agent 1 — verifies receipt submission flow")
KEY2=$(register_entity "ep-test-sender-2" "Test Sender Beta" "Pipeline test agent 2 — verifies multi-submitter scoring")
KEY3=$(register_entity "ep-test-sender-3" "Test Sender Gamma" "Pipeline test agent 3 — verifies establishment threshold")

echo ""

# Check if we got keys
if [ "$KEY1" = "FAILED" ] || [ "$KEY1" = "ALREADY_EXISTS" ] || \
   [ "$KEY2" = "FAILED" ] || [ "$KEY2" = "ALREADY_EXISTS" ] || \
   [ "$KEY3" = "FAILED" ] || [ "$KEY3" = "ALREADY_EXISTS" ]; then
  echo -e "${RED}Some registrations failed or entities already exist.${NC}"
  echo "If entities already exist, you need their API keys."
  echo "You can re-run with fresh entity IDs, or manually set keys below."
  echo ""
  echo "To use fresh IDs, edit this script and change ep-test-sender-1/2/3"
  echo "to ep-test-sender-4/5/6 (or any unused IDs)."
  echo ""
  
  # If any key is missing, we can't continue
  if [ "$KEY1" = "FAILED" ] || [ "$KEY2" = "FAILED" ] || [ "$KEY3" = "FAILED" ]; then
    echo -e "${RED}Aborting due to registration failures.${NC}"
    exit 1
  fi
  
  if [ "$KEY1" = "ALREADY_EXISTS" ] || [ "$KEY2" = "ALREADY_EXISTS" ] || [ "$KEY3" = "ALREADY_EXISTS" ]; then
    echo -e "${GOLD}Paste API keys for existing entities (or press Enter to skip that sender):${NC}"
    if [ "$KEY1" = "ALREADY_EXISTS" ]; then
      read -p "  Key for ep-test-sender-1: " KEY1
    fi
    if [ "$KEY2" = "ALREADY_EXISTS" ]; then
      read -p "  Key for ep-test-sender-2: " KEY2
    fi
    if [ "$KEY3" = "ALREADY_EXISTS" ]; then
      read -p "  Key for ep-test-sender-3: " KEY3
    fi
  fi
fi

# -------------------------------------------
# STEP 2: Submit receipts about Rex (v1 format)
# -------------------------------------------
echo -e "${GOLD}[2] Submitting v1 receipts about Rex...${NC}"

submit_receipt() {
  local API_KEY=$1
  local TARGET=$2
  local BODY=$3
  local LABEL=$4
  
  if [ -z "$API_KEY" ] || [ "$API_KEY" = "ALREADY_EXISTS" ]; then
    echo -e "  ${GOLD}⚠${NC} Skipping $LABEL — no API key"
    return
  fi
  
  local RESULT=$(curl -s -X POST "$BASE/api/receipts/submit" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -d "$BODY")
  
  local RECEIPT_ID=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('receipt',{}).get('receipt_id',''))" 2>/dev/null)
  local ERR=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)
  local SCORE=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('entity_score',{}).get('emilia_score','?'))" 2>/dev/null)
  
  if [ -n "$RECEIPT_ID" ] && [ "$RECEIPT_ID" != "" ]; then
    echo -e "  ${GREEN}✓${NC} $LABEL → receipt=$RECEIPT_ID, new_score=$SCORE"
  else
    echo -e "  ${RED}✗${NC} $LABEL failed: $ERR"
    echo "    Full response: $RESULT"
  fi
}

# Sender 1 → Rex: Great booking experience
submit_receipt "$KEY1" "rex-booking-v1" '{
  "entity_id": "rex-booking-v1",
  "transaction_ref": "test-txn-001",
  "transaction_type": "service",
  "delivery_accuracy": 95,
  "product_accuracy": 90,
  "price_integrity": 100,
  "agent_behavior": "completed"
}' "Sender1→Rex (excellent)"

# Sender 2 → Rex: Good but slightly late
submit_receipt "$KEY2" "rex-booking-v1" '{
  "entity_id": "rex-booking-v1",
  "transaction_ref": "test-txn-002",
  "transaction_type": "service",
  "delivery_accuracy": 78,
  "product_accuracy": 92,
  "price_integrity": 100,
  "agent_behavior": "completed"
}' "Sender2→Rex (good, late)"

# Sender 3 → Rex: Perfect
submit_receipt "$KEY3" "rex-booking-v1" '{
  "entity_id": "rex-booking-v1",
  "transaction_ref": "test-txn-003",
  "transaction_type": "service",
  "delivery_accuracy": 100,
  "product_accuracy": 95,
  "price_integrity": 100,
  "agent_behavior": "completed"
}' "Sender3→Rex (perfect)"

echo ""

# -------------------------------------------
# STEP 3: Submit receipts about Ruby (v1 format)
# -------------------------------------------
echo -e "${GOLD}[3] Submitting v1 receipts about Ruby...${NC}"

# Sender 1 → Ruby: Great retention campaign
submit_receipt "$KEY1" "ruby-retention-v1" '{
  "entity_id": "ruby-retention-v1",
  "transaction_ref": "test-txn-004",
  "transaction_type": "service",
  "delivery_accuracy": 88,
  "product_accuracy": 94,
  "price_integrity": 100,
  "agent_behavior": "completed"
}' "Sender1→Ruby (great)"

# Sender 2 → Ruby: Retry needed
submit_receipt "$KEY2" "ruby-retention-v1" '{
  "entity_id": "ruby-retention-v1",
  "transaction_ref": "test-txn-005",
  "transaction_type": "service",
  "delivery_accuracy": 85,
  "product_accuracy": 80,
  "price_integrity": 100,
  "agent_behavior": "retried_same"
}' "Sender2→Ruby (retried)"

# Sender 3 → Ruby: Excellent
submit_receipt "$KEY3" "ruby-retention-v1" '{
  "entity_id": "ruby-retention-v1",
  "transaction_ref": "test-txn-006",
  "transaction_type": "service",
  "delivery_accuracy": 92,
  "product_accuracy": 96,
  "price_integrity": 100,
  "agent_behavior": "completed"
}' "Sender3→Ruby (excellent)"

echo ""

# -------------------------------------------
# STEP 4: Submit a v2 claims-based receipt
# -------------------------------------------
echo -e "${GOLD}[4] Submitting v2 claims-based receipt about Rex...${NC}"

submit_receipt "$KEY1" "rex-booking-v1" '{
  "entity_id": "rex-booking-v1",
  "transaction_ref": "test-txn-007",
  "transaction_type": "service",
  "claims": {
    "delivered": true,
    "on_time": {
      "promised": "2026-03-14T10:00:00Z",
      "actual": "2026-03-14T09:30:00Z"
    },
    "price_honored": {
      "quoted_cents": 19900,
      "charged_cents": 19900
    },
    "as_described": true
  },
  "evidence": {
    "booking_ref": "BK-20260314-001",
    "payment_ref": "stripe_pi_test123"
  },
  "agent_behavior": "completed"
}' "Sender1→Rex (v2 claims)"

echo ""

# -------------------------------------------
# STEP 5: Add more receipts to reach establishment (5+ from 3+ submitters)
# -------------------------------------------
echo -e "${GOLD}[5] Submitting additional receipts to reach establishment threshold...${NC}"

submit_receipt "$KEY2" "rex-booking-v1" '{
  "entity_id": "rex-booking-v1",
  "transaction_ref": "test-txn-008",
  "transaction_type": "service",
  "delivery_accuracy": 90,
  "product_accuracy": 88,
  "price_integrity": 95,
  "agent_behavior": "completed"
}' "Sender2→Rex (5th receipt)"

submit_receipt "$KEY3" "ruby-retention-v1" '{
  "entity_id": "ruby-retention-v1",
  "transaction_ref": "test-txn-009",
  "transaction_type": "service",
  "delivery_accuracy": 90,
  "product_accuracy": 92,
  "price_integrity": 100,
  "agent_behavior": "completed"
}' "Sender3→Ruby (4th receipt)"

submit_receipt "$KEY1" "ruby-retention-v1" '{
  "entity_id": "ruby-retention-v1",
  "transaction_ref": "test-txn-010",
  "transaction_type": "service",
  "delivery_accuracy": 94,
  "product_accuracy": 91,
  "price_integrity": 100,
  "agent_behavior": "completed"
}' "Sender1→Ruby (5th receipt)"

echo ""

# -------------------------------------------
# STEP 6: Verify scores changed
# -------------------------------------------
echo -e "${GOLD}[6] Verifying scores...${NC}"
echo ""

REX_AFTER=$(curl -s "$BASE/api/score/rex-booking-v1")
RUBY_AFTER=$(curl -s "$BASE/api/score/ruby-retention-v1")

REX_SCORE_AFTER=$(echo "$REX_AFTER" | python3 -c "import json,sys; print(json.load(sys.stdin)['emilia_score'])" 2>/dev/null)
REX_RECEIPTS_AFTER=$(echo "$REX_AFTER" | python3 -c "import json,sys; print(json.load(sys.stdin)['total_receipts'])" 2>/dev/null)
REX_ESTABLISHED=$(echo "$REX_AFTER" | python3 -c "import json,sys; print(json.load(sys.stdin)['established'])" 2>/dev/null)
REX_BREAKDOWN=$(echo "$REX_AFTER" | python3 -c "import json,sys; d=json.load(sys.stdin)['breakdown']; print(f'delivery={d[\"delivery_accuracy\"]}, product={d[\"product_accuracy\"]}, price={d[\"price_integrity\"]}') if d else print('(not established)')" 2>/dev/null)

RUBY_SCORE_AFTER=$(echo "$RUBY_AFTER" | python3 -c "import json,sys; print(json.load(sys.stdin)['emilia_score'])" 2>/dev/null)
RUBY_RECEIPTS_AFTER=$(echo "$RUBY_AFTER" | python3 -c "import json,sys; print(json.load(sys.stdin)['total_receipts'])" 2>/dev/null)
RUBY_ESTABLISHED=$(echo "$RUBY_AFTER" | python3 -c "import json,sys; print(json.load(sys.stdin)['established'])" 2>/dev/null)
RUBY_BREAKDOWN=$(echo "$RUBY_AFTER" | python3 -c "import json,sys; d=json.load(sys.stdin)['breakdown']; print(f'delivery={d[\"delivery_accuracy\"]}, product={d[\"product_accuracy\"]}, price={d[\"price_integrity\"]}') if d else print('(not established)')" 2>/dev/null)

echo -e "${CYAN}  ┌──────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}  │           RESULTS                                │${NC}"
echo -e "${CYAN}  ├──────────────────────────────────────────────────┤${NC}"
echo -e "${CYAN}  │  Rex (rex-booking-v1)                            │${NC}"
echo -e "${CYAN}  │    Before: score=$REX_SCORE_BEFORE, receipts=$REX_RECEIPTS_BEFORE${NC}"
echo -e "${CYAN}  │    After:  score=$REX_SCORE_AFTER, receipts=$REX_RECEIPTS_AFTER${NC}"
echo -e "${CYAN}  │    Established: $REX_ESTABLISHED${NC}"
echo -e "${CYAN}  │    Breakdown: $REX_BREAKDOWN${NC}"
echo -e "${CYAN}  ├──────────────────────────────────────────────────┤${NC}"
echo -e "${CYAN}  │  Ruby (ruby-retention-v1)                        │${NC}"
echo -e "${CYAN}  │    Before: score=$RUBY_SCORE_BEFORE, receipts=$RUBY_RECEIPTS_BEFORE${NC}"
echo -e "${CYAN}  │    After:  score=$RUBY_SCORE_AFTER, receipts=$RUBY_RECEIPTS_AFTER${NC}"
echo -e "${CYAN}  │    Established: $RUBY_ESTABLISHED${NC}"
echo -e "${CYAN}  │    Breakdown: $RUBY_BREAKDOWN${NC}"
echo -e "${CYAN}  └──────────────────────────────────────────────────┘${NC}"
echo ""

# -------------------------------------------
# STEP 7: Verify leaderboard
# -------------------------------------------
echo -e "${GOLD}[7] Checking leaderboard...${NC}"
LEADERBOARD=$(curl -s "$BASE/api/leaderboard")
LB_TOTAL=$(echo "$LEADERBOARD" | python3 -c "import json,sys; print(json.load(sys.stdin).get('total',0))" 2>/dev/null)
echo "  Leaderboard entries: $LB_TOTAL"
echo ""

# -------------------------------------------
# STEP 8: Check stats
# -------------------------------------------
echo -e "${GOLD}[8] Checking stats...${NC}"
STATS=$(curl -s "$BASE/api/stats")
echo "  $STATS"
echo ""

# -------------------------------------------
# VERDICT
# -------------------------------------------
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
if [ "$REX_SCORE_AFTER" != "50" ] && [ "$RUBY_SCORE_AFTER" != "50" ]; then
  echo -e "${GREEN}  ✓ PIPELINE WORKS — Rex and Ruby have real scores${NC}"
  echo -e "${GREEN}  ✓ Protocol is functional. Ready to ship.${NC}"
else
  echo -e "${RED}  ✗ Scores didn't change — check receipt submission logs${NC}"
  echo -e "${RED}  Run: vercel logs --follow${NC}"
fi
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "Next: Check the live site at https://emiliaprotocol.ai"
echo "  - Score lookup should show real data for rex-booking-v1"
echo "  - Entity profiles at /entity/rex-booking-v1"
echo ""

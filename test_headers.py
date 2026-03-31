from app.detection.engine import analyze

headers = {
    "Host": "localhost:8080",
    "Connection": "keep-alive",
    "sec-ch-ua": "\"Google Chrome\";v=\"123\", \"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"123\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9"
}

res = analyze(endpoint='/app/dashboard-v2-final', payload='', headers=headers)
print("Dashboard Match:", res.matched_rule, res.attack_type, res.all_matches)

res2 = analyze(endpoint='/favicon.ico', payload='', headers=headers)
print("Favicon Match:", res2.matched_rule, res2.attack_type, res2.all_matches)

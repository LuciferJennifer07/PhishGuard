import re
import urllib.parse

def check_phishing(subject, body, sender=""):
    text = (subject + " " + body).lower()
    score = 0
    reasons = []

    # --- Whitelist: common legit domains / brands (usefully reduces false positives) ---
    whitelist_domains = [
        "gmail.com", "google.com", "microsoft.com", "outlook.com", "paypal.com",
        "amazon.com", "facebook.com", "netflix.com", "linkedin.com"
    ]

    # --- Suspicious TLDs (keep as before, used for combos) ---
    suspicious_exts = [
        ".xyz", ".top", ".tk", ".ga", ".cf", ".ml", ".gq", ".cn", ".ru", ".biz", ".info", ".pw",
        ".click", ".link", ".fit", ".rest", ".cam", ".live", ".buzz", ".site", ".space", ".online",
        ".store", ".support", ".cloud", ".fun", ".icu", ".tech", ".win", ".party", ".vip",
        ".review", ".trade", ".bid", ".surf", ".wiki", ".zone", ".email", ".solutions",
        ".cheap", ".discount", ".rewards", ".offers", ".coupon"
    ]

    # --- Keywords split into two classes ---
    # low_weight_keywords: common words that appear in legit emails too
    low_weight_keywords = [
        "login", "signin", "account", "update", "password", "support", "service", "billing"
    ]

    # high_weight_keywords: more suspicious or action-oriented phrases
    high_weight_phrases = [
        r"verify (your )?account", r"verify-now", r"confirm (your )?account", r"reset (your )?password",
        r"click (here|the link) to", r"urgent (action )?", r"suspend(ed|ing)? account", r"reactivate (your )?account",
        r"provide your password", r"enter your password", r"transaction (failed|notice)"
    ]

    # generic suspicious keywords that are more risky when combined with suspicious TLD or URL
    suspicious_url_keywords = [
        "secure", "verify", "confirm", "bank", "authentication", "billing", "reset",
        "unlock", "webmail", "wallet", "invoice", "payment", "refund", "reimburse", "claim",
        "gift", "bonus", "offer", "alert", "suspend", "limited", "urgent", "verify-now"
    ]

    # --- find urls ---
    urls = re.findall(r"(https?://[^\s]+|[A-Za-z0-9.-]+\.[A-Za-z]{2,})", text)

    # --- 1) high-weight phrase detection in body/subject (strong signal) ---
    matched_high = []
    for pat in high_weight_phrases:
        if re.search(r"\b" + pat + r"\b", text):
            matched_high.append(pat)
    if matched_high:
        reasons.append(f"⚠️ Found suspicious imperative phrases: {', '.join([p.strip('\\\\') for p in matched_high])}")
        score += 25 * len(matched_high)  # strong penalty per phrase

    # --- 2) low-weight keywords (reduce per-key score) ---
    found_low = [w for w in low_weight_keywords if re.search(r"\b" + re.escape(w) + r"\b", text)]
    if found_low:
        reasons.append(f"ℹ️ Common suspicious words (low weight): {', '.join(found_low)}")
        score += len(found_low) * 5  # only small increase

    # --- 3) inspect URLs carefully (URL presence is important) ---
    url_hits = []
    for u in urls:
        u_lower = u.lower()
        # parse to extract netloc domain if possible
        parsed = urllib.parse.urlparse(u_lower if "://" in u_lower else "http://" + u_lower)
        domain = parsed.netloc or parsed.path  # fallback
        domain = domain.strip("/")

        # skip if domain is explicitly whitelisted (exact or contains)
        if any(w in domain for w in whitelist_domains):
            # record but don't penalize
            continue

        # detect suspicious tld presence
        tld_flag = any(domain.endswith(ext) or ext in domain for ext in suspicious_exts)
        kw_flag = any(kw in u_lower for kw in suspicious_url_keywords)

        # if URL contains explicit high-risk phrase or matches a high phrase
        if any(re.search(r"\b" + p + r"\b", u_lower) for p in ["verify", "confirm", "reset-password", "secure-login"]):
            reasons.append(f"🚨 URL has action-oriented token: {u}")
            score += 18

        # If URL uses suspicious TLD AND keyword present -> stronger signal
        if tld_flag and kw_flag:
            reasons.append(f"🚨 Suspicious TLD + keyword in URL: {u}")
            score += 25
        elif tld_flag:
            reasons.append(f"⚠️ Suspicious TLD in URL: {u}")
            score += 12
        elif kw_flag:
            # keyword in URL but not suspicious TLD -> medium signal
            reasons.append(f"⚠️ Suspicious keyword in URL: {u}")
            score += 10

        # URL shorteners or IP addresses detection (extra signal)
        if re.search(r"https?://\d{1,3}(?:\.\d{1,3}){3}", u_lower):
            reasons.append(f"⚠️ URL uses raw IP: {u}")
            score += 18
        if re.search(r"(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|adf\.ly|shorturl\.at|rebrand\.ly)", u_lower):
            reasons.append(f"⚠️ URL is shortened (might hide final destination): {u}")
            score += 15

        url_hits.append(u)

    if url_hits:
        # small baseline boost if any URLs exist (phish often include links)
        score += 8
        reasons.append(f"🔗 Found links: {', '.join(url_hits[:3])}")

    # --- 4) sender / brand mismatch heuristic
    if sender:
        sender_lower = sender.lower()
        # try to detect common brand names in email body/subject and compare sender domain
        brands = ["paypal", "amazon", "google", "microsoft", "netflix", "bank"]
        for b in brands:
            if re.search(r"\b" + re.escape(b) + r"\b", text) and b not in sender_lower:
                # if brand mentioned but sender not from that brand -> suspicious
                reasons.append(f"⚠️ Brand '{b}' mentioned but sender not from {b}: {sender}")
                score += 18
                break

        # generic-looking sender addresses are slightly suspicious but low weight
        if any(x in sender_lower for x in ["no-reply", "noreply", "do-not-reply", "support@", "info@", "admin@", "service@"]):
            reasons.append(f"ℹ️ Generic-looking sender address: {sender}")
            score += 4

    # --- 5) final caps / thresholding and caps ---
    score = int(min(score, 100))

    return score, reasons

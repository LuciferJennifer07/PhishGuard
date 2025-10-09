import re
import streamlit as st

# ---- Page Config ----
st.set_page_config(page_title="PhishGuard - Simple Phishing Detector", layout="wide")

# ---- Header ----
st.markdown("<h1 style='text-align:center; color:#00FF00;'>🛡️ PhishGuard</h1>", unsafe_allow_html=True)
st.markdown("<h4 style='text-align:center; color:#00FF88;'>Simple Phishing Email Detector</h4>", unsafe_allow_html=True)
st.markdown("<h5 style='text-align:center; color:#00FF88;'>Made by Team - Error420</h5>", unsafe_allow_html=True)
st.markdown("<h6 style='text-align:center; color:#00FF88;'>Team Members: Yuvraj Tyagi, Shivam, Palak Khandelwal, Palak Agrawal</h6>", unsafe_allow_html=True)
st.markdown("---")

# ---- Centered Input Section ----
st.markdown("<h4 style='text-align:center; color:#FFFFFF;'>Enter Email Details</h4>", unsafe_allow_html=True)
sender = st.text_input("Sender Email (optional)", key="sender")
subject = st.text_input("Email Subject", key="subject")
body = st.text_area("Email Body", height=200, key="body")
analyze_btn = st.button("🔍 Analyze Email")

# ---- Phishing Detection Function ----
def check_phishing(subject, body, sender=""):
    text = (subject + " " + body).lower()
    score = 0
    reasons = []

    # ⚠️ Expanded suspicious words (more coverage)
    suspicious_words = [
        "urgent", "verify", "login", "password", "bank", "account", "update", "click", "confirm",
        "secure", "suspend", "limited", "alert", "warning", "confirm-now", "reset", "authentication",
        "wallet", "invoice", "payment", "paypal", "amazon", "bonus", "offer", "prize", "claim",
        "billing", "refund", "helpdesk", "support", "security", "urgent-action", "verify-now",
        "reset-password", "transaction", "immediate", "important", "reactivate"
    ]
    found_words = [w for w in suspicious_words if w in text]
    if found_words:
        reasons.append(f"⚠️ Found suspicious words: {', '.join(found_words)}")
        score += len(found_words) * 10

    # 🔗 Advanced phishing-prone extensions and keywords
    suspicious_exts = [
        ".xyz", ".top", ".tk", ".ga", ".cf", ".ml", ".gq", ".cn", ".ru", ".biz", ".info", ".pw",
        ".click", ".link", ".fit", ".rest", ".cam", ".live", ".buzz", ".site", ".space", ".online",
        ".store", ".support", ".cloud", ".fun", ".icu", ".tech", ".win", ".party", ".vip",
        ".review", ".trade", ".bid", ".surf", ".wiki", ".zone", ".email", ".solutions",
        ".cheap", ".discount", ".rewards", ".offers", ".coupon"
    ]

    suspicious_url_keywords = [
        "login", "signin", "secure", "verify", "account", "update", "password", "confirm", "bank",
        "authentication", "billing", "reset", "unlock", "service", "support", "helpdesk", "webmail",
        "outlook", "wallet", "gift", "bonus", "offer", "alert", "suspend", "limited", "urgent",
        "verify-now", "confirm-now", "paypal", "amazon", "appleid", "microsoft", "google", "facebook"
    ]

    urls = re.findall(r"(https?://[^\s]+|[A-Za-z0-9.-]+\.[A-Za-z]{2,})", text)
    if urls:
        reasons.append(f"🔗 Found links: {', '.join(urls[:3])}")
        score += 20
        for u in urls:
            u_lower = u.lower()
            # Match suspicious extension or keyword
            if any(ext in u_lower for ext in suspicious_exts) or any(k in u_lower for k in suspicious_url_keywords):
                reasons.append(f"🚨 Suspicious link: {u}")
                score += 15

    # 📨 Sender analysis
    if sender and any(x in sender.lower() for x in ["no-reply", "support@", "noreply", "help@", "info@", "service@", "admin@", "care@"]):
        reasons.append(f"📩 Sender looks generic: {sender}")
        score += 5

    score = min(score, 100)
    return score, reasons

# ---- Analyze Button Logic ----
if analyze_btn:
    if not subject and not body:
        st.warning("Please enter email subject or body.")
    else:
        score, reasons = check_phishing(subject, body, sender)

        # ---- Result Card ----
        if score >= 70:
            color = "#FF4B4B"
            status = "⚠️ High Risk Phishing Email"
            st.snow()  # small animation for alert
        elif score >= 40:
            color = "#FFA500"
            status = "⚠️ Potential Phishing Email"
        else:
            color = "#32CD32"
            status = "✅ Email looks Legitimate"

        st.markdown(f"""
            <div style='background-color:#1e1e1e; padding:20px; border-radius:10px; border-left:10px solid {color}; text-align:center;'>
                <h3 style='color:{color}'>{status} ({score}/100)</h3>
            </div>
            """, unsafe_allow_html=True)

        # ---- Gradient Progress Bar ----
        st.markdown(f"""
        <div style='background-color:#333333; border-radius:10px; height:25px; margin-top:10px;'>
            <div style='width:{score}%; background: linear-gradient(90deg, #00FF00, #00FFFF); height:25px; border-radius:10px;'></div>
        </div>
        """, unsafe_allow_html=True)

        # ---- Reasons Section ----
        with st.expander("🔍 Why this result?"):
            if reasons:
                for r in reasons:
                    st.write(r)
            else:
                st.write("No suspicious elements found!")

# ---- Footer ----
st.markdown("---")
st.markdown(
    """
    <div style='text-align:center; color:#00FF00; margin-top:20px;'>
        <strong>Made by Team - Error420</strong><br>
        Team Members: Yuvraj Tyagi, Shivam, Palak Khandelwal, Palak Agrawal
    </div>
    """,
    unsafe_allow_html=True
)

st.info("🧠 *Note: Beginner-friendly prototype. Future improvements: AI-based analysis, metadata checks, advanced phishing detection.*")

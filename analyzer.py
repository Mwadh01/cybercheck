import re
from urllib.parse import urlparse

def classify(stats):
    mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
    if mal > 3:
        return "danger", "تحذير! هذا العنصر مصنّف كخبيث أو تصيّد."
    if mal > 0 or sus > 0:
        return "suspicious", "تنبيه: هناك مؤشرات مشبوهة، توخَّ الحذر."
    return "safe", "لم يتم العثور على أي تهديد."

def local_url_score(url):
    """فحص محلي بسيط: كل مؤشر يزيد النقاط"""
    score, reasons = 0, []
    host = urlparse(url).hostname or ""
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        score += 2; reasons.append("الرابط يستخدم عنوان IP بدل اسم نطاق")
    if len(url) > 75:
        score += 1; reasons.append("الرابط طويل بشكل غير معتاد")
    if "@" in url:
        score += 2; reasons.append("الرابط يحتوي على رمز @")
    if any(w in url.lower() for w in ["login", "verify", "update", "secure", "bank"]):
        score += 1; reasons.append("يحتوي كلمات شائعة في التصيّد")
    if host.count(".") >= 4:
        score += 1; reasons.append("عدد كبير من النطاقات الفرعية")
    return score, reasons
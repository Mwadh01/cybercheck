import requests
from flask import Flask, request, jsonify, render_template
import vt_client, db, analyzer

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32MB
db.init_db()

def vt_error(e):
    if isinstance(e, requests.exceptions.HTTPError) and e.response is not None:
        code = e.response.status_code
        if code == 429:
            return "تجاوزت الحد المسموح من الطلبات، انتظر دقيقة وحاول مرة أخرى."
        if code in (401, 403):
            return "مشكلة في مفتاح VirusTotal، تحقق من ملف .env."
        if code == 404:
            return "لم يتم العثور على نتيجة الفحص."
    if isinstance(e, requests.exceptions.Timeout):
        return "انتهت مهلة الاتصال بخدمة الفحص، حاول مرة أخرى."
    if isinstance(e, requests.exceptions.ConnectionError):
        return "تعذر الاتصال بالإنترنت أو بخدمة الفحص."
    return "حدث خطأ غير متوقع أثناء الفحص."

@app.errorhandler(413)
def too_big(e):
    return jsonify({"error": "حجم الملف أكبر من 32MB"}), 413

@app.get("/")
def home(): return render_template("index.html")
@app.get("/result")
def result_page(): return render_template("result.html")
@app.get("/dashboard")
def dashboard(): return render_template("dashboard.html")
@app.get("/history")
def history_page(): return render_template("history.html")

@app.post("/api/scan-url")
def scan_url():
    url = (request.json or {}).get("url", "").strip()
    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "رابط غير صالح، لازم يبدأ بـ http:// أو https://"}), 400
    try:
        aid = vt_client.submit_url(url)
    except requests.exceptions.RequestException as e:
        return jsonify({"error": vt_error(e)}), 502
    db.save_scan(aid, url, "url")
    return jsonify({"id": aid})

@app.post("/api/scan-file")
def scan_file():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "لم يتم رفع ملف"}), 400
    try:
        aid = vt_client.submit_file(f)
    except requests.exceptions.RequestException as e:
        return jsonify({"error": vt_error(e)}), 502
    db.save_scan(aid, f.filename, "file")
    return jsonify({"id": aid})

@app.get("/api/result/<aid>")
def result(aid):
    try:
        done, stats = vt_client.get_analysis(aid)
    except requests.exceptions.RequestException as e:
        return jsonify({"error": vt_error(e)}), 502
    if not done:
        return jsonify({"done": False})
    status, msg = analyzer.classify(stats)
    db.update_status(aid, status)
    return jsonify({"done": True, "status": status, "message": msg, "stats": stats})

@app.get("/api/history")
def api_history(): return jsonify(db.history())
@app.get("/api/stats")
def api_stats(): return jsonify(db.stats())

if __name__ == "__main__":
    app.run(debug=False)
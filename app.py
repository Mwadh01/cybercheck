from flask import Flask, request, jsonify, render_template
import vt_client, db, analyzer

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32MB
db.init_db()

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
        return jsonify({"error": "رابط غير صالح"}), 400
    aid = vt_client.submit_url(url)
    db.save_scan(aid, url, "url")
    return jsonify({"id": aid})

@app.post("/api/scan-file")
def scan_file():
    f = request.files.get("file")
    if not f: return jsonify({"error": "لم يتم رفع ملف"}), 400
    aid = vt_client.submit_file(f)
    db.save_scan(aid, f.filename, "file")
    return jsonify({"id": aid})

@app.get("/api/result/<aid>")
def result(aid):
    done, stats = vt_client.get_analysis(aid)
    if not done: return jsonify({"done": False})
    status, msg = analyzer.classify(stats)
    db.update_status(aid, status)
    return jsonify({"done": True, "status": status, "message": msg, "stats": stats})

@app.get("/api/history")
def api_history(): return jsonify(db.history())
@app.get("/api/stats")
def api_stats(): return jsonify(db.stats())

if __name__ == "__main__":
    app.run(debug=True)
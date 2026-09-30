import os, requests
from dotenv import load_dotenv
load_dotenv()

BASE = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": os.getenv("VT_API_KEY")}

def submit_url(url):
    r = requests.post(f"{BASE}/urls", headers=HEADERS, data={"url": url}, timeout=30)
    r.raise_for_status()
    return r.json()["data"]["id"]

def submit_file(file_storage):
    files = {"file": (file_storage.filename, file_storage.stream)}
    r = requests.post(f"{BASE}/files", headers=HEADERS, files=files, timeout=60)
    r.raise_for_status()
    return r.json()["data"]["id"]

def get_analysis(analysis_id):
    r = requests.get(f"{BASE}/analyses/{analysis_id}", headers=HEADERS, timeout=30)
    r.raise_for_status()
    attrs = r.json()["data"]["attributes"]
    return attrs["status"] == "completed", attrs["stats"]
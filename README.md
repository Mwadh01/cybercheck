# SaudiCheck 🛡️

An Arabic web application that scans suspicious URLs and files for threats using the VirusTotal API, and classifies them as safe 🟢, suspicious 🟡, or dangerous 🔴.

**Live demo:** https://cybercheck-rtz4.onrender.com

## Features
- Scan URLs and files (up to 32 MB) against 70+ security engines
- Clear color-coded results in Arabic
- Scan history and a statistics dashboard
- Clear error messages for rate limits, invalid keys, and network failures

## Tech Stack
Python, Flask, SQLite, JavaScript, HTML/CSS, VirusTotal API, Render

## Security
- API key stored in environment variables, never in the source code
- Debug mode disabled in production
- Input validation for URLs and file size limits

## How It Works
1. The user submits a URL or file
2. The server validates it and sends it to VirusTotal
3. The page checks for the result every 3 seconds (polling)
4. The result is classified, saved, and shown to the user

## Run Locally
```bash
pip install -r requirements.txt
# create a .env file with: VT_API_KEY=your_key
python app.py
```

## Author
Mawadah Abdulaziz – Cybersecurity Diploma Student

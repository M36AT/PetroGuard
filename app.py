import requests
import json
import os
import re
from dotenv import load_dotenv
import google.generativeai as genai
import sqlite3
from flask import Flask, jsonify, render_template, request

# --- 1. INITIALIZE FLASK & DATABASE ---
app = Flask(__name__)
DB_FILE = "threat_profiles.db"

def init_db():
    """Initializes the database and creates tables if they don't exist."""
    print("Initializing database...")
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    # This table tracks "sources" (e.g., Wikipedia, NewsAPI)
    cur.execute('''
    CREATE TABLE IF NOT EXISTS source_profiles (
        source_name TEXT PRIMARY KEY,
        flag_count INTEGER DEFAULT 0,
        last_seen TEXT
    )''')
    # This table tracks harmful keywords
    cur.execute('''
    CREATE TABLE IF NOT EXISTS keyword_trends (
        keyword TEXT PRIMARY KEY,
        count INTEGER DEFAULT 0
    )''')
    con.commit()
    con.close()

# --- 2. CONFIGURATION ---
load_dotenv()

# Gemini API config
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or "YOUR_FALLBACK_KEY" # (Using fallback from your code)
genai.configure(api_key=GEMINI_API_KEY)

API_CONFIGS = [
    {
        "name": "NewsAPI",
        "type": "newsapi",
        "base_url": "https://newsapi.org/v2/everything",
        "api_key": os.getenv("NEWSAPI_KEY") or "YOUR_FALLBACK_KEY" # (Using fallback from your code)
    },
    {
        "name": "NewsData.io",
        "type": "newsdata",
        "base_url": "https://newsdata.io/api/1/latest",
        "api_key": os.getenv("NEWSDATA_KEY") or "YOUR_FALLBACK_KEY" # (Using fallback from your code)
    },
    {
        "name": "Wikipedia",
        "type": "wikipedia",
        "base_url": "https://en.wikipedia.org/w/api.php"
    }
]

HARMFUL_KEYWORDS = [
    "scam", "fraud", "bomb", "attack", "terror", "hack", "threat",
    "arrested", "kill", "bad", "murder", "shoot"
]

# --- 3. DATABASE "WRITE" FUNCTIONS ---

def update_source_profile(source_name):
    """Updates the flag count for a given news source."""
    if not source_name:
        source_name = "unknown_source"
    try:
        con = sqlite3.connect(DB_FILE)
        cur = con.cursor()
        cur.execute('''
            INSERT INTO source_profiles (source_name, flag_count, last_seen)
            VALUES (?, 1, CURRENT_TIMESTAMP)
            ON CONFLICT(source_name) DO UPDATE SET
                flag_count = flag_count + 1,
                last_seen = CURRENT_TIMESTAMP
        ''', (source_name,))
        con.commit()
        con.close()
        print(f"  [DB] Updated profile for: {source_name}")
    except Exception as e:
        print(f"  [DB ERROR] {e}")


def update_keyword_trends(keywords):
    """Increments the count for a list of harmful keywords."""
    if not keywords:
        return
    try:
        con = sqlite3.connect(DB_FILE)
        cur = con.cursor()
        for kw in keywords:
            cur.execute('''
                INSERT INTO keyword_trends (keyword, count)
                VALUES (?, 1)
                ON CONFLICT(keyword) DO UPDATE SET
                    count = count + 1
            ''', (kw,))
            print(f"  [DB] Incremented trend for: {kw}")
        con.commit()
        con.close()
    except Exception as e:
        print(f"  [DB ERROR] {e}")

# --- 4. YOUR ANALYSIS FUNCTIONS (Copied from your script) ---

def fetch_all_news(api_configs, query, language="en", country="my", max_results=10):
    all_articles = []
    headers = {"User-Agent": "my-osint-tool/1.0 (contact: you@example.com)"}

    for api in api_configs:
        print(f"\n🔎 Fetching from: {api.get('name', 'unknown')}")
        api_type = api.get("type")
        params = {} # Init params
        if api_type == "wikipedia":
            params = {"action": "query", "list": "search", "srsearch": query, "format": "json", "srlimit": max_results}
        elif api_type == "newsdata":
            params = {"q": query, "language": language, "country": country, "apikey": api.get("api_key")}
        else:  # NewsAPI or similar
            params = {"q": query, "language": language, "pageSize": max_results, "apiKey": api.get("api_key")}

        try:
            resp = requests.get(api["base_url"], params=params, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            print(f"[ERROR] {api.get('name', 'API')} failed: {e}")
            continue

        articles = []
        if api_type == "wikipedia":
            for item in data.get("query", {}).get("search", []):
                articles.append({"source": "Wikipedia", "title": item.get("title"), "description": re.sub("<.*?>", "", item.get("snippet", "")), "link": f"https://en.wikipedia.org/?curid={item.get('pageid')}", "pub_date": "", "keywords": [], "api_type": "wikipedia"})
        elif api_type == "newsdata":
            if data.get("status") != "success": continue
            for item in data.get("results", []):
                articles.append({"source": item.get("source_id") or item.get("source_name") or "NewsData.io", "title": item.get("title"), "description": item.get("description") or "", "link": item.get("link"), "pub_date": item.get("pubDate"), "keywords": item.get("keywords") or [], "api_type": "news"})
        else:  # NewsAPI or similar
            if data.get("status") != "ok": continue
            for item in data.get("articles", []):
                articles.append({"source": item.get("source", {}).get("name", "NewsAPI"), "title": item.get("title"), "description": item.get("description") or "", "link": item.get("url"), "pub_date": item.get("publishedAt"), "keywords": [], "api_type": "news"})

        print(f"[INFO] {api.get('name', 'API')} -> {len(articles)} articles")
        all_articles.extend(articles)

    print(f"\n✅ Total articles found: {len(all_articles)}")
    return all_articles

def detect_harmful_words(text):
    found = set()
    if text:
        for word in HARMFUL_KEYWORDS:
            if re.search(r'\b{}\b'.format(re.escape(word)), str(text), re.IGNORECASE):
                found.add(word.lower())
    return list(found)

def fetch_from_gemini_sentiment_intent(text, harm_words):
    prompt = (
        "You are analyzing potentially harmful or scam-related news.\n"
        "I will provide news/article content and a list of detected harmful words.\n"
        "Please classify:\n"
        "- Sentiment: one of [positive1, positive2, negative1, negative2, neutral]\n"
        "- Intent: one of [harmful1, harmful2, harmless1, harmless2]\n"
        "Definitions:\n"
        "- positive1: mildly positive, positive2: strongly positive.\n"
        "- negative1: mildly negative, negative2: highly negative.\n"
        "- harmful1: contains mild threat/scam indicators, harmful2: high threat/scam/severe issue.\n"
        "- harmless1: content totally safe, harmless2: content with minor caution but not an actual threat.\n"
        "Base your answer on the article and the detected harmful words.\n"
        "Return in the exact format:\n"
        "SENTIMENT={sentiment_label} INTENT={intent_label} REASON={short_reason}\n\n"
        f"Article: {text}\n"
        f"Harmful words: {harm_words}\n"
    )
    try:
        # --- FIXED MODEL NAME ---
        # 'gemini-2.5-flash' does not exist.
        # 'gemini-pro' is the standard model that will work.
        model = genai.GenerativeModel("gemini-pro")
        response = model.generate_content(prompt)
        return response.text.strip() if hasattr(response, "text") else str(response)
    except Exception as e:
        return f"[Gemini API error: {e}]"

def full_categorize(articles):
    categorized = []
    for article in articles:
        harmful_in_title = detect_harmful_words(article.get('title', ''))
        harmful_in_desc = detect_harmful_words(article.get('description', ''))
        harmful_in_keywords = [
            word for kw in (article.get('keywords') or [])
            for word in HARMFUL_KEYWORDS if word in str(kw).lower()
        ]
        harmful_words = set(harmful_in_title + harmful_in_desc + harmful_in_keywords)

        text = (article.get('title') or '') + ". " + (article.get('description') or '')
        gemini_result = fetch_from_gemini_sentiment_intent(
            text=text,
            harm_words=', '.join(harmful_words) if harmful_words else "None"
        )
        
        sentiment_label = ""
        intent_label = ""
        reason_text = ""
        if "SENTIMENT=" in gemini_result and "INTENT=" in gemini_result:
            try:
                sentiment_label = re.search(r'SENTIMENT=([a-zA-Z0-9]+)', gemini_result).group(1)
                intent_label = re.search(r'INTENT=([a-zA-Z0-9]+)', gemini_result).group(1)
                reason_match = re.search(r'REASON=(.*)', gemini_result)
                reason_text = reason_match.group(1).strip() if reason_match else ""
            except Exception:
                pass

        is_harmful = intent_label.startswith("harmful")

        article['harmful'] = is_harmful
        article['harmful_words'] = list(harmful_words)
        article['gemini_sentiment'] = sentiment_label
        article['gemini_intent'] = intent_label
        article['gemini_reason'] = reason_text
        article['gemini_raw'] = gemini_result

        categorized.append(article)
    return categorized

# --- 5. FLASK ROUTES ---

@app.route('/')
def route_login():
    """Serves the login.html page from the 'templates' folder."""
    return render_template('login.html')

@app.route('/dashboard')
def route_dashboard():
    """Serves the dashboard.html page."""
    return render_template('dashboard.html')

@app.route('/api/analyze')
def api_analyze():
    """
    This is the main API endpoint your JavaScript will call.
    It runs the full analysis and updates the database.
    """
    query = request.args.get('q', None)
    if not query:
        return jsonify({"error": "A 'q' (query) parameter is required"}), 400
    
    print(f"--- API HIT: processing query '{query}' ---")
    
    # 1. Fetch news (using your logic)
    all_hits = fetch_all_news(API_CONFIGS, query, max_results=5) # Kept max_results low for a fast demo
    
    # 2. Analyze with Gemini (using your logic)
    categorized_hits = full_categorize(all_hits)
    
    # 3. --- UPDATE DATABASE ---
    #    This is the "memory" part.
    print("--- Analysis Complete. Updating Database... ---")
    for article in categorized_hits:
        if article.get('harmful'):
            # update the source profile
            update_source_profile(article.get('source', 'unknown_source'))
            
            # update the keyword trends
            update_keyword_trends(article.get('harmful_words', []))
            
    # 4. Return the final list as JSON
    return jsonify(categorized_hits)

@app.route('/api/profiles')
def get_profiles():
    """Endpoint for your dashboard to get source profile data."""
    con = sqlite3.connect(DB_FILE)
    con.row_factory = sqlite3.Row # Makes the output a dict
    cur = con.cursor()
    cur.execute("SELECT * FROM source_profiles ORDER BY flag_count DESC LIMIT 20")
    sources = [dict(row) for row in cur.fetchall()]
    con.close()
    return jsonify(sources)

@app.route('/api/trends')
def get_trends():
    """Endpoint for your dashboard to get keyword trend data."""
    con = sqlite3.connect(DB_FILE)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM keyword_trends ORDER BY count DESC LIMIT 20")
    keywords = [dict(row) for row in cur.fetchall()]
    con.close()
    return jsonify(keywords)

# --- 6. RUN THE FLASK APP ---
if __name__ == "__main__":
    init_db() # Create the database file and tables on first run
    app.run(host-'0.0.0.0', debug=True)


import requests
import json
import os
import re
from dotenv import load_dotenv
import google.generativeai as genai

# --- 1. CONFIGURATION ---
load_dotenv()

# Gemini API config
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or "AIzaSyCwE27btugQ7bSPHfDNEimNJ25tAmlbx2c"
genai.configure(api_key=GEMINI_API_KEY)

API_CONFIGS = [
    {
        "name": "NewsAPI",
        "type": "newsapi",
        "base_url": "https://newsapi.org/v2/everything",
        "api_key": os.getenv("NEWSAPI_KEY") or "48a4a9f04f424d1887c8b635bc8e9786"
    },
    {
        "name": "NewsData.io",
        "type": "newsdata",
        "base_url": "https://newsdata.io/api/1/latest",
        "api_key": os.getenv("NEWSDATA_KEY") or "pub_2cacf136af4d4ffb9fa5e8b8c00b3cef"
    },
    {
        "name": "Wikipedia",
        "type": "wikipedia",
        "base_url": "https://en.wikipedia.org/w/api.php"
        # Wikipedia does not need an API key
    }
]

HARMFUL_KEYWORDS = [
    "scam", "fraud", "bomb", "attack", "terror", "hack", "threat",
    "arrested", "kill", "bad", "murder", "shoot"
]

# --- FETCHING FROM ALL APIS (NewsAPI + NewsData + Wikipedia) ---
def fetch_all_news(api_configs, query, language="en", country="my", max_results=10):
    all_articles = []
    headers = {"User-Agent": "my-osint-tool/1.0 (contact: you@example.com)"}

    for api in api_configs:
        print(f"\n🔎 Fetching from: {api.get('name', 'unknown')}")
        api_type = api.get("type")

        # --- Build params per API type ---
        if api_type == "wikipedia":
            params = {
                "action": "query",
                "list": "search",
                "srsearch": query,
                "format": "json",
                "srlimit": max_results
            }
        elif api_type == "newsdata":
            params = {
                "q": query,
                "language": language,
                "country": country,
                "apikey": api.get("api_key")
            }
        else:  # NewsAPI or similar
            params = {
                "q": query,
                "language": language,
                "pageSize": max_results,
                "apiKey": api.get("api_key")
            }

        # --- Call the API ---
        try:
            resp = requests.get(api["base_url"], params=params, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            print(f"[ERROR] {api.get('name', 'API')} failed: {e}")
            continue

        # --- Parse and normalize results ---
        articles = []
        if api_type == "wikipedia":
            for item in data.get("query", {}).get("search", []):
                articles.append({
                    "source": "Wikipedia",
                    "title": item.get("title"),
                    "description": re.sub("<.*?>", "", item.get("snippet", "")),
                    "link": f"https://en.wikipedia.org/?curid={item.get('pageid')}",
                    "pub_date": "",
                    "keywords": [],
                    "api_type": "wikipedia"
                })
        elif api_type == "newsdata":
            if data.get("status") != "success":
                print("[WARN] NewsData.io returned non-success status")
                continue
            for item in data.get("results", []):
                articles.append({
                    "source": item.get("source_id") or item.get("source_name") or "NewsData.io",
                    "title": item.get("title"),
                    "description": item.get("description") or "",
                    "link": item.get("link"),
                    "pub_date": item.get("pubDate"),
                    "keywords": item.get("keywords") or [],
                    "api_type": "news"
                })
        else:  # NewsAPI or similar
            if data.get("status") != "ok":
                print("[WARN] NewsAPI returned non-ok status")
                continue
            for item in data.get("articles", []):
                articles.append({
                    "source": item.get("source", {}).get("name", "NewsAPI"),
                    "title": item.get("title"),
                    "description": item.get("description") or "",
                    "link": item.get("url"),
                    "pub_date": item.get("publishedAt"),
                    "keywords": [],
                    "api_type": "news"
                })

        print(f"[INFO] {api.get('name', 'API')} -> {len(articles)} articles")
        all_articles.extend(articles)

    print(f"\n✅ Total articles found: {len(all_articles)}")
    return all_articles

# --- Simple harmful keyword detection (for context only) ---
def detect_harmful_words(text):
    found = set()
    if text:
        for word in HARMFUL_KEYWORDS:
            if re.search(r'\b{}\b'.format(re.escape(word)), str(text), re.IGNORECASE):
                found.add(word.lower())
    return list(found)

# --- Gemini helper: classify sentiment + intent ---
def fetch_from_gemini_sentiment_intent(text, harm_words):
    """
    Ask Gemini to classify:
    - Sentiment (positive1, positive2, negative1, negative2, neutral)
    - Intent (harmful1, harmful2, harmless1, harmless2)
    Rely ONLY on Gemini to decide harmfulness.
    """
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
        model = genai.GenerativeModel("gemini-2.5-flash")
        response = model.generate_content(prompt)
        return response.text.strip() if hasattr(response, "text") else str(response)
    except Exception as e:
        return f"[Gemini API error: {e}]"

# --- Full categorization relying on Gemini ---
def full_categorize(articles):
    categorized = []
    for article in articles:
        # Detect harmful words in title / description / keywords (for context to Gemini)
        harmful_in_title = detect_harmful_words(article.get('title', ''))
        harmful_in_desc = detect_harmful_words(article.get('description', ''))
        harmful_in_keywords = [
            word for kw in (article.get('keywords') or [])
            for word in HARMFUL_KEYWORDS if word in str(kw).lower()
        ]
        harmful_words = set(harmful_in_title + harmful_in_desc + harmful_in_keywords)

        # Compose text for Gemini
        text = (article.get('title') or '') + ". " + (article.get('description') or '')
        gemini_result = fetch_from_gemini_sentiment_intent(
            text=text,
            harm_words=', '.join(harmful_words) if harmful_words else "None"
        )

        # Extract sentiment and intent from Gemini's response
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

        # Decide harmful flag ONLY from Gemini's intent
        is_harmful = intent_label.startswith("harmful")

        article['harmful'] = is_harmful
        article['harmful_words'] = list(harmful_words)
        article['gemini_sentiment'] = sentiment_label
        article['gemini_intent'] = intent_label
        article['gemini_reason'] = reason_text
        article['gemini_raw'] = gemini_result

        categorized.append(article)

    return categorized

# ---- MAIN EXECUTION ----
if __name__ == "__main__":
    TARGET_KEYWORDS = str(input("Enter targeted keyword: ")).strip()
    TARGET_COUNTRY = "my"
    TARGET_LANGUAGE = "en"
    MAX_RESULTS = 5  # you can increase later

    all_hits = fetch_all_news(
        API_CONFIGS, TARGET_KEYWORDS, TARGET_LANGUAGE, TARGET_COUNTRY, MAX_RESULTS
    )

    all_hits = full_categorize(all_hits)

    print("\n--- OSINT News Report ---")
    if all_hits:
        for i, article in enumerate(all_hits[:10]):
            print(f"\n# HIT {i+1}")
            print(f"  Title: {article['title']}")
            print(f"  Source: {article['source']} ({article.get('pub_date', '')})")
            print(f"  Link: {article['link']}")
            print(f"  Description: {article['description']}")
            print(f"  Gemini Sentiment: {article.get('gemini_sentiment', '')}")
            print(f"  Gemini Intent: {article.get('gemini_intent', '')}")
            print(f"  Reason: {article.get('gemini_reason', '')}")
            print(f"  Harmful Words (detected): {article.get('harmful_words', [])}")
            if article['harmful']:
                print("  [DANGER] Gemini flagged this as harmful content!")
            else:
                print("  [OK] Gemini did not flag this as harmful.")

        # Save results
        with open("news_osint_results.json", 'w', encoding="utf-8") as f:
            json.dump(all_hits, f, indent=4, ensure_ascii=False)
        print(f"\n✅ All {len(all_hits)} results saved to news_osint_results.json")
    else:
        print("No valid articles found!")

    print("\n--- Harmful News Only ---")
    for i, article in enumerate(all_hits):
        if article['harmful']:
            print(f"\n[DANGER] {article['title']}")
            print(f"  Source: {article['source']}")
            print(f"  Link: {article['link']}")
            print(f"  Gemini Intent: {article.get('gemini_intent', '')}")
            print(f"  Reason: {article.get('gemini_reason', '')}")
            print(f"  Harmful Words: {article.get('harmful_words', [])}")


import requests

def github_poc_search(cve_id, github_token=None):
    headers = {"Accept": "application/vnd.github+json"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    query = f"{cve_id} in:file"
    url = f"https://api.github.com/search/code?q={query}&per_page=5"

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        data = resp.json()
        results = data.get("items", [])
        return [item["html_url"] for item in results]
    except Exception as e:
        print(f"GitHub search failed for {cve_id}: {e}")
        return []
    
github_poc_search("2025-24813", None)
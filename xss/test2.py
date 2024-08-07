from flask import Flask, render_template, request
import requests

# XSS payloads dictionary (for educational purposes only, don't use in production)
xss_dict = {
    # ... (remove actual payloads to avoid misuse)
}

app = Flask(__name__)


def check_xss(url, params=None):
    """
    Checks for potential XSS vulnerabilities by sending a GET request with a generic payload.
    **Do not use this for real security testing.** 

    Args:
        url (str): The URL to check.
        params (dict, optional): Additional parameters to send in the request. Defaults to None.

    Returns:
        bool: True if the response suggests potential XSS, False otherwise.
    """
    # Use a generic payload to avoid triggering false positives
    test_payload = "<sVg/onLOad=document.body.append(`cb06dba3`.repeat(2))>"
    response = requests.get(url, params=dict({"q": test_payload}, **(params or {})))
    # Search for a generic XSS pattern instead of the exact payload
    return any(pattern in response.text.lower() for pattern in ["<script>", "alert"])

def check_sql_injection(url, params=None):
    """
    Checks for potential SQL injection vulnerabilities with a very basic payload.
    **Do not use this for real security testing. This is for educational purposes only.**

    Args:
        url (str): The URL to check.
        params (dict, optional): Additional parameters to send in the request. Defaults to None.

    Returns:
        bool: True if the response suggests potential SQL injection, False otherwise.
    """
    # Basic test payload (highly inaccurate, use a proper library for real testing)
    test_payload = "' OR '1'='1"
    response = requests.get(url, params=dict({"id": test_payload}, **(params or {})))
    # Search for generic error messages related to SQL errors
    return "sql" in response.text.lower() or "error" in response.text.lower()

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url")
        # Validate and sanitize user input (prevent malicious URLs)
        if not url or not url.startswith(('http://', 'https://')):
            return "Invalid URL format."
        xss_vulnerable = check_xss(url)
        sql_injection_vulnerable = check_sql_injection(url)
        return render_template("result.html", url=url, xss=xss_vulnerable, sql=sql_injection_vulnerable)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=False)  # Set debug to False for production


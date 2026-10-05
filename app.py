from flask import Flask, render_template, request
from vt_checker import check_url

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    url = request.form["url"].strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = check_url(url)

    return render_template(
        "result.html",
        url=url,
        result=result
    )


if __name__ == "__main__":
    app.run(debug=True)
"""Showcase service: each route reaches a different vulnerable dependency, so deph
traces several CVEs as in-path (not just present)."""
import yaml
import requests
from flask import Flask, request
from jinja2 import Template

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def load_config():
    # Reachable use of the vulnerable yaml.load (pyyaml CVE-2020-14343).
    return yaml.load(request.data, Loader=yaml.FullLoader)


@app.route("/proxy")
def proxy():
    # Reachable use of requests / urllib3.
    return requests.get(request.args["url"]).text


@app.route("/render")
def render():
    # Reachable use of jinja2 templating.
    return Template(request.args.get("tpl", "")).render()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

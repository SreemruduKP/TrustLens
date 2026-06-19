from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse

app = FastAPI()

class URLInput(BaseModel):
    url: str

@app.get("/")
def home():
    return{"status":"running", "project":"TrustLens"}

def extract_url_parts(netloc):
    parts=netloc.split(".")
    if len(parts) >=3:
        subdomain = parts[0]
        domain = ".".join(parts[1:])
    else:
        subdomain = None
        domain = netloc
    return subdomain,domain

@app.post("/analyse-url")

def analyse_url(data: URLInput):
    parsed = urlparse(data.url)
    subdomain, domain = extract_url_parts(parsed.netloc)
    return{
        "orginal_url" : data.url,
        "scheme" : parsed.scheme,
        "subdomain" : subdomain,
        "domain" : domain,
        "path" : parsed.path,
        "query" : parsed.query,
        "is_https" : parsed.scheme == "https",
        "warning": "No HTTPS — connection not encrypted" if parsed.scheme != "https" else None
        }
from whois_check import get_domain_age
from fastapi import FastAPI
from pydantic import BaseModel
from predictor import predict_url

app = FastAPI()

class URLInput(BaseModel):
    url: str

@app.get("/")
def home():
    return{"status":"running", "project":"TrustLens"}

@app.post("/analyse-url")

def analyse_url(data: URLInput):
    url = data.url
    
    ml_result = predict_url(url)

    whois_result = get_domain_age(url)


    return {
        "url": url,
        "prediction": ml_result["prediction"],
        "risk_score": ml_result["risk_score"],
        "risk_level": ml_result["risk_level"],
        "confidence": ml_result["confidence"],
        "domain_age_days": whois_result["age_days"],
        "creation_date": whois_result["creation_date"],
        "registrar": whois_result["registrar"],
        "age_risk": whois_result["age_risk"]
    } 
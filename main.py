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
    result = predict_url(url)
    return result
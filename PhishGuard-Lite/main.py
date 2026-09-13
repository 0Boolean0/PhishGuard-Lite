import re
import joblib
import numpy as np
from urllib.parse import urlparse
from collections import Counter
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

# Allow extension to call local server without CORS blocks
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load your trained model
MODEL_PATH = "phishguard_model.pkl" # Make sure path is correct
try:
    model = joblib.load(MODEL_PATH)
    print("Loaded ML Model successfully!")
except Exception as e:
    print(f"Error loading model: {e}")

class URLRequest(BaseModel):
    url: str

def extract_features(url: str):
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else parsed.path
    
    length = len(url)
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    has_at = 1 if '@' in url else 0
    
    ip_pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
    has_ip = 1 if re.search(ip_pattern, domain) else 0
    
    has_https = 1 if parsed.scheme == 'https' else 0
    keywords = ['login', 'verify', 'secure', 'account', 'update', 'banking', 'signin', 'admin', 'pay']
    num_keywords = sum(1 for kw in keywords if kw in url.lower())
    num_digits = sum(c.isdigit() for c in url)
    
    def calc_entropy(text):
        if not text: return 0
        counts = Counter(text)
        return -sum((c / len(text)) * np.log2(c / len(text)) for c in counts.values())

    domain_entropy = calc_entropy(domain)
    return [length, num_dots, num_hyphens, has_at, has_ip, has_https, num_keywords, num_digits, domain_entropy]

@app.post("/predict")
def predict(request: URLRequest):
    features = extract_features(request.url)
    prediction = model.predict([features])[0]
    probabilities = model.predict_proba([features])[0]
    confidence = float(probabilities[prediction])
    
    return {
        "url": request.url,
        "is_phishing": bool(prediction == 1),
        "confidence": round(confidence * 100, 2)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
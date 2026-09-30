from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from models import PaymentRequest
from risk_engine import analyze_payment

app = FastAPI(title="Sentra API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {"message": "Sentra backend is running"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/payment-request")
def create_payment_request(request: PaymentRequest):
    risk_score, risk_level, signals = analyze_payment(
        amount=request.amount,
        recipient=request.recipient,
        message=request.message,
        link=request.link,
    )

    return {
        "message": "Payment analyzed",
        "amount": request.amount,
        "recipient": request.recipient,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "signals": signals,
    }

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from models import PaymentRequest

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

    # Start with a neutral score
    risk_score = 10
    signals = []

    # Amount analysis
    if request.amount > 10000:
        risk_score += 50
        signals.append("High-value payment")
    elif request.amount > 1000:
        risk_score += 25
        signals.append("Elevated payment amount")

    # Recipient analysis
    recipient = request.recipient.lower().strip()

    if "unknown" in recipient:
        risk_score += 25
        signals.append("Unknown recipient")

    # Link analysis
    link = request.link.lower().strip()

    if link:
        risk_score += 15
        signals.append("Payment link detected")

    # Message analysis
    message = request.message.lower()

    suspicious_words = [
        "urgent",
        "verify",
        "otp",
        "password",
        "immediately",
        "account blocked",
    ]

    for word in suspicious_words:
        if word in message:
            risk_score += 10
            signals.append(f"Suspicious language: {word}")

    # Keep score between 0 and 100
    risk_score = min(risk_score, 100)

    # Determine risk level
    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 35:
        risk_level = "REVIEW"
    else:
        risk_level = "SAFE"

    return {
        "message": "Payment analyzed",
        "amount": request.amount,
        "recipient": request.recipient,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "signals": signals,
    }
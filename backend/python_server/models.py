from pydantic import BaseModel, Field


class PaymentRequest(BaseModel):
    amount: float = Field(gt=0)
    recipient: str = Field(min_length=1)
    message: str = ""
    link: str = ""

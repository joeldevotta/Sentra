from pydantic import BaseModel, Field


from pydantic import BaseModel, Field


class PaymentRequest(BaseModel):
    amount: float = Field(gt=0)
    recipient: str
    message: str = ""
    link: str = ""

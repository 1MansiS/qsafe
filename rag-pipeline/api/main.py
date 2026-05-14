from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="qsafe RAG service")


class RetrieveRequest(BaseModel):
    primitive: str
    usage: str
    top_k: int = 5


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/retrieve")
def retrieve(req: RetrieveRequest):
    return [
        {
            "text": f"[stub] primitive={req.primitive} usage={req.usage} — real retrieval not yet implemented.",
            "source": "stub",
            "section": "stub",
            "score": 1.0,
        }
    ]

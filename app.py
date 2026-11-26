from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any

app = FastAPI(
    title="Harness Engineering 2026",
    version="1.0"
)


class ClassificationRequest(BaseModel):
    profile: str
    batchId: str
    policy: dict[str, Any]
    cases: list[dict[str, Any]]


@app.get("/")
def home():
    return {
        "status": "running",
        "message": "Harness Engineering API"
    }


@app.post("/classify")
def classify(request: ClassificationRequest):

    results = []

    for case in request.cases:
        results.append({
            "caseId": case.get("caseId"),
            "requestDecision": "review",
            "toolDecision": (
                "review"
                if case.get("proposedTool") is not None
                else "none"
            ),
            "route": "primary",
            "trajectory": "watch"
        })

    return {
        "profile": "agent-harness-2026-09",
        "batchId": request.batchId,
        "results": results
    }

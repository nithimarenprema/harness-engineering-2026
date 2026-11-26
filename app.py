import os
import re
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

PROFILE = "agent-harness-2026-09"

app = FastAPI(title="Harness Engineering API")


class ClassificationRequest(BaseModel):
    profile: str
    batchId: str
    policy: dict[str, Any]
    cases: list[dict[str, Any]]


def user_messages(case):
    return [
        m.get("content", "")
        for m in case.get("messages", [])
        if isinstance(m, dict)
        and m.get("role") == "user"
        and isinstance(m.get("content", ""), str)
    ]


def classify_case(case, policy):
    messages = user_messages(case)
    text = " ".join(messages).lower()

    tool = case.get("proposedTool")
    has_tool = isinstance(tool, dict)

    resolved = tool.get("resolved", {}) if has_tool else {}
    operation = str(resolved.get("operation", "")).lower()
    target = str(resolved.get("target", "")).lower()
    environment = str(resolved.get("environment", "")).lower()

    harmful_patterns = [
        r"\bsteal\b.{0,60}\b(password|credentials?|tokens?)",
        r"\bexfiltrate\b.{0,60}\b(private data|credentials?)",
        r"\bcommit fraud\b",
        r"\bdestructive malware\b",
        r"\bcreate ransomware\b",
        r"\bharass\b.{0,40}\breal person",
        r"\bhelp me\b.{0,40}\b(injure|kill)\b",
    ]

    harmful = any(re.search(p, text) for p in harmful_patterns)

    security_terms = [
        "penetration test", "vulnerability", "exploit",
        "sql injection", "cross-site scripting",
        "security test", "xss"
    ]
    security_work = any(term in text for term in security_terms)

    ownership_terms = [
        "my own system", "my own server",
        "owned by me", "our own server",
        "authorized target", "explicit permission"
    ]
    ownership_clear = any(term in text for term in ownership_terms)

    env = case.get("environment", {})
    isolation = env.get("isolation", {})

    isolated = (
        env.get("kind") == "container"
        and isolation.get("verified") is True
        and isolation.get("hostMounts") == []
        and isolation.get("credentials") is False
        and isolation.get("externalNetwork") is False
    )

    if harmful:
        request_decision = "block"
    elif security_work and not (ownership_clear and isolated):
        request_decision = "review"
    else:
        request_decision = "allow"

    if not has_tool:
        tool_decision = "none"
    else:
        args = str(tool.get("arguments", {})).lower()
        effects = operation + " " + target + " " + environment + " " + args

        if harmful:
            tool_decision = "block"

        elif not operation or not target or not environment:
            tool_decision = "review"

        elif any(word in effects for word in [
            "production", "external", "privileged",
            "personal machine", "host"
        ]):
            tool_decision = "review"

        elif any(word in args for word in [
            "password", "secret", "credential", "token"
        ]) and any(word in args for word in [
            "find", "search", "grep", "scan"
        ]):
            tool_decision = "block"

        elif operation in ["read", "list", "inspect", "view"]:
            tool_decision = "allow"

        elif operation in ["write", "edit", "modify", "create"]:
            tool_decision = "allow"

        elif operation == "delete":
            disposable = resolved.get("disposable") is True
            safe_container = (
                env.get("kind") == "container"
                and isolation.get("verified") is True
                and isolation.get("hostMounts") == []
                and isolation.get("credentials") is False
                and isolation.get("externalNetwork") is False
            )
            fixture_task = "fixture-cleanup experiment" in text
            safe_target = target.startswith("/work/")

            if disposable and safe_container and fixture_task and safe_target:
                tool_decision = "allow"
            else:
                tool_decision = "review"
        else:
            tool_decision = "review"

    if request_decision == "block":
        tool_decision = "block" if has_tool else "none"

    elif request_decision == "review" and tool_decision != "block":
        tool_decision = "review" if has_tool else "none"

    if request_decision == "block":
        route = "none"
    elif security_work:
        route = "restricted"
    else:
        route = "primary"

    if request_decision == "block" or tool_decision == "block":
        trajectory = "intervene"
    elif request_decision == "review" or tool_decision == "review":
        trajectory = "watch"
    else:
        trajectory = "normal"

    return {
        "caseId": case["caseId"],
        "requestDecision": request_decision,
        "toolDecision": tool_decision,
        "route": route,
        "trajectory": trajectory
    }


@app.get("/")
def home():
    return {"status": "running", "profile": PROFILE}


@app.post("/classify")
def classify(request: ClassificationRequest):
    if request.profile != PROFILE:
        raise HTTPException(status_code=400, detail="Invalid profile")

    if not request.batchId:
        raise HTTPException(status_code=400, detail="Missing batchId")

    if len(request.cases) != 24:
        raise HTTPException(status_code=400, detail="Exactly 24 cases required")

    ids = [
        case.get("caseId")
        for case in request.cases
        if isinstance(case, dict)
    ]

    if (
        len(ids) != 24
        or any(not isinstance(i, str) or not i for i in ids)
        or len(set(ids)) != 24
    ):
        raise HTTPException(status_code=400, detail="Invalid or duplicate case IDs")

    results = [
        classify_case(case, request.policy)
        for case in request.cases
    ]

    return {
        "profile": PROFILE,
        "batchId": request.batchId,
        "results": results
    }

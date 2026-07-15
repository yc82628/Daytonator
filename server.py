"""DayTonator web server.

Wraps the detonation pipeline in a tiny FastAPI app and serves the console UI.
Run from the project root:

    uvicorn server:app --reload --port 8000

Then open http://localhost:8000

By default it uses the LocalRunner (offline, no keys). Set BACKEND=daytona in the
environment to use real Daytona forking once your DAYTONA_API_KEY is set.
"""
from __future__ import annotations
try:
    from dotenv import load_dotenv; load_dotenv()
except Exception:
    pass
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from detonator.runner import LocalRunner, DaytonaRunner
from detonator.pipeline import detonate_package
from detonator.baits import DEFAULT_BAITS, MVP_BAITS

app = FastAPI(title="DayTonator")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


DEMOS = {
    "benign-demo": ("demo_packages/benign_demo", "benign_demo"),
    "canary-stealer": ("demo_packages/canary_stealer", "canary_stealer"),
    "evasive-stealer": ("demo_packages/evasive_stealer", "evasive_stealer"),
}


def _runner():
    if os.environ.get("BACKEND") == "daytona":
        r = DaytonaRunner()
    else:
        r = LocalRunner()
    r.prepare()
    return r


class DetonateRequest(BaseModel):
    package: str
    full: bool = True


@app.get("/")
def index():
    return FileResponse(os.path.join(os.path.dirname(__file__), "web", "index.html"))


@app.get("/api/demos")
def demos():
    return {"demos": list(DEMOS.keys())}


@app.post("/api/detonate")
def detonate(req: DetonateRequest):
    baits = DEFAULT_BAITS if req.full else MVP_BAITS
    local_path, import_name = DEMOS.get(req.package, (None, None))
    try:
        runner = _runner()
        det = detonate_package(
            runner, req.package, baits=baits,
            import_name=import_name, local_path=local_path,
        )
        runner.cleanup()
        return det.to_dict()
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

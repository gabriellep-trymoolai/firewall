from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from dotenv import load_dotenv
import openai
import os
import time
import logging
import datetime

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from perspective import PerspectiveAPI
from firewall_lists import BLOCK_LIST, ALLOW_LIST
from llamafirewall import (
    LlamaFirewall,
    Role,
    ScannerType,
    UserMessage,
    ScanDecision
)
from pii_scanner import check_pii
from secrets_scanner import check_secrets

load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
DB_URL = os.getenv("DB_URL")

if not OPENAI_API_KEY:
    raise EnvironmentError("OPENAI_API_KEY is not set.")
if not DB_URL:
    raise EnvironmentError("DB_URL is not set.")

openai.api_key = OPENAI_API_KEY
perspective_client = PerspectiveAPI()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

app = FastAPI()

lf = LlamaFirewall(
    scanners={
        Role.USER: [ScannerType.PROMPT_GUARD],
        Role.SYSTEM: [ScannerType.PROMPT_GUARD],
    }
)

engine = create_engine(DB_URL)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

class LLMResult(Base):
    __tablename__ = "llm_results"
    id = Column(Integer, primary_key=True, index=True)
    question = Column(String(512))
    selected_model = Column(String(128))
    latency = Column(Float)
    input_tokens = Column(Integer)
    output_tokens = Column(Integer)
    date = Column(DateTime, default=datetime.datetime.utcnow)
    month = Column(Integer)
    year = Column(Integer)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class PromptRequest(BaseModel):
    prompt: str

class RouteLLMResponse(BaseModel):
    response: str
    model_used: str
    latency: float
    input_tokens: int
    output_tokens: int

def check_allowlist(text: str):
    return any(word.lower() in text.lower() for word in ALLOW_LIST)

def check_blocklist(text: str):
    return any(word.lower() in text.lower() for word in BLOCK_LIST)

def check_prompt_injection(prompt: str):
    result = lf.scan(UserMessage(content=prompt))
    if result.decision == ScanDecision.BLOCK:
        raise HTTPException(status_code=403, detail="Blocked: Prompt injection detected")

def full_scan(prompt: str):
    check_prompt_injection(prompt)  # Run this first for maximum security
    if not check_allowlist(prompt):
        raise HTTPException(status_code=403, detail="Blocked: not finance-related")
    if check_blocklist(prompt):
        raise HTTPException(status_code=403, detail="Blocked: banned word found")
    pii = check_pii(prompt)
    if pii:
        raise HTTPException(status_code=403, detail=f"Blocked: {pii} detected")
    if check_secrets(prompt):
        raise HTTPException(status_code=403, detail="Blocked: potential secret detected")

def check_output_toxicity(text: str):
    scores = perspective_client.score(
        text,
        attributes=["TOXICITY", "SEVERE_TOXICITY", "INSULT", "THREAT", "IDENTITY_ATTACK"]
    )
    for label, score in scores.items():
        if score > 0.7:
            raise HTTPException(status_code=403, detail=f"Blocked: {label} detected in output")

def call_openai(prompt: str):
    start = time.time()
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}]
    )
    end = time.time()
    return RouteLLMResponse(
        response=response.choices[0].message.content,
        model_used="gpt-3.5-turbo",
        latency=end - start,
        input_tokens=response.usage.prompt_tokens,
        output_tokens=response.usage.completion_tokens
    )

@app.post("/process_prompt", response_model=RouteLLMResponse)
async def process_prompt(request: PromptRequest, db: Session = Depends(get_db)):
    logger.info(f"Received prompt: {request.prompt[:50]}...")
    full_scan(request.prompt)
    llm_response = call_openai(request.prompt)
    check_output_toxicity(llm_response.response)

    now = datetime.datetime.utcnow()
    db_result = LLMResult(
        question=request.prompt,
        selected_model=llm_response.model_used,
        latency=llm_response.latency,
        input_tokens=llm_response.input_tokens,
        output_tokens=llm_response.output_tokens,
        date=now,
        month=now.month,
        year=now.year,
    )
    db.add(db_result)
    db.commit()

    logger.info(f"Returned in {llm_response.latency:.2f}s.")
    return llm_response

@app.post("/test/allowlist")
async def test_allowlist(request: PromptRequest):
    if not check_allowlist(request.prompt):
        raise HTTPException(status_code=403, detail="Blocked: not in allowlist")
    return {"status": "✅ Allowlist passed"}

@app.post("/test/blocklist")
async def test_blocklist(request: PromptRequest):
    if check_blocklist(request.prompt):
        raise HTTPException(status_code=403, detail="Blocked: contains blocked term")
    return {"status": "✅ Blocklist passed"}

@app.post("/test/pii")
async def test_pii(request: PromptRequest):
    pii = check_pii(request.prompt)
    if pii:
        raise HTTPException(status_code=403, detail=f"Blocked: {pii} detected")
    return {"status": "✅ PII check passed"}

@app.post("/test/secrets")
async def test_secrets(request: PromptRequest):
    if check_secrets(request.prompt):
        raise HTTPException(status_code=403, detail="Blocked: potential secret detected")
    return {"status": "✅ Secrets check passed"}
    
@app.post("/test/promptinjection")
async def test_promptinjection(request: PromptRequest):
    try:
        check_prompt_injection(request.prompt)
    except HTTPException as e:
        raise e
    return {"status": "✅ Prompt injection check passed"}
    
@app.on_event("startup")
async def startup():
    logger.info("✅ Server started with input & output firewall and DB logging.")
    Base.metadata.create_all(bind=engine)
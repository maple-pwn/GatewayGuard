# Security Fixes Implementation Guide

## Quick Start - Critical Fixes (Do This First)

### 1. LLM Prompt Injection Protection (15 minutes)

**Create:** `backend/app/utils/security.py`
```python
import re
from typing import List

INJECTION_PATTERNS = [
    r"ignore\s+(previous|all|above)\s+instructions?",
    r"system\s+prompt",
    r"reveal\s+(secret|key|password|token)",
    r"<\|im_start\|>",
    r"<\|im_end\|>",
]

def sanitize_llm_input(text: str, max_length: int = 2000) -> str:
    """Sanitize user input before LLM processing."""
    text = text[:max_length]
    text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
    
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            raise ValueError("Potentially malicious input detected")
    
    return text.strip()

def filter_llm_output(response: str) -> str:
    """Remove sensitive information from LLM responses."""
    patterns = [
        (r'sk-[a-zA-Z0-9]{48}', '[REDACTED_API_KEY]'),
        (r'postgresql://[^\s]+', '[REDACTED_DB_URL]'),
        (r'Bearer\s+[a-zA-Z0-9\-._~+/]+=*', '[REDACTED_TOKEN]'),
    ]
    
    for pattern, replacement in patterns:
        response = re.sub(pattern, replacement, response)
    
    return response
```

**Update:** `backend/app/routers/chat.py`
```python
from app.utils.security import sanitize_llm_input, filter_llm_output
from fastapi import HTTPException

@router.post("/chat")
async def chat(req: ChatRequest):
    try:
        sanitized_message = sanitize_llm_input(req.message)
        # ... existing logic ...
        response = await llm_service.chat(sanitized_message, req.session_id)
        filtered_response = filter_llm_output(response)
        return {"response": filtered_response}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
```

---

### 2. File Upload Path Traversal Fix (10 minutes)

**Update:** `backend/app/routers/traffic.py`
```python
import os
import uuid
from pathlib import Path
from fastapi import HTTPException

def sanitize_filename(filename: str) -> str:
    """Generate safe filename for uploads."""
    ext = Path(filename).suffix.lower()
    
    if ext not in ['.pcap', '.pcapng', '.cap']:
        raise ValueError(f"Invalid file type: {ext}")
    
    return f"{uuid.uuid4()}{ext}"

@router.post("/upload")
async def upload_pcap(file: UploadFile):
    safe_filename = sanitize_filename(file.filename)
    file_path = os.path.join(UPLOAD_DIR, safe_filename)
    
    # Verify path is within UPLOAD_DIR
    real_path = os.path.realpath(file_path)
    real_upload_dir = os.path.realpath(UPLOAD_DIR)
    
    if not real_path.startswith(real_upload_dir):
        raise HTTPException(400, "Invalid file path")
    
    # ... save file
```

---

### 3. Rate Limiting (20 minutes)

**Install:**
```bash
pip install slowapi
```

**Create:** `backend/app/middleware/rate_limit.py`
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
```

**Update:** `backend/app/main.py`
```python
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.middleware.rate_limit import limiter

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
```

**Apply to endpoints:**
```python
from fastapi import Request
from app.middleware.rate_limit import limiter

@router.post("/detect")
@limiter.limit("10/minute")
async def detect_anomalies(request: Request, ...):
    pass

@router.post("/chat")
@limiter.limit("20/minute")
async def chat(request: Request, req: ChatRequest):
    pass
```

---

### 4. Request Size Limits (5 minutes)

**Update:** `backend/app/main.py`
```python
from fastapi.responses import JSONResponse

@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    if request.method in ["POST", "PUT"]:
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > 10_000_000:  # 10MB
            return JSONResponse(
                status_code=413,
                content={"detail": "Request too large"}
            )
    return await call_next(request)
```

---

## Phase 2: Authentication (Day 2)

### Install Dependencies
```bash
pip install python-jose[cryptography] passlib[bcrypt]
```

### Create Auth System

**File:** `backend/app/auth/dependencies.py`
```python
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from app.config import settings

security = HTTPBearer()

async def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.SECRET_KEY,
            algorithms=["HS256"]
        )
        return payload
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )
```

**Apply to all endpoints:**
```python
from app.auth.dependencies import verify_token

@router.post("/detect")
async def detect_anomalies(
    user: dict = Depends(verify_token),
    ...
):
    pass
```

---

## Phase 3: Input Validation (Day 3)

### Update Pydantic Models

**File:** `backend/app/models/packet.py`
```python
from pydantic import BaseModel, validator, Field
from datetime import datetime

class UnifiedPacket(BaseModel):
    timestamp: float = Field(ge=0, le=2147483647)
    protocol: str = Field(max_length=20)
    msg_id: str = Field(max_length=50)
    payload_hex: str = Field(max_length=512)
    
    @validator('timestamp')
    def validate_timestamp(cls, v):
        if v > datetime.now().timestamp() + 86400:
            raise ValueError("Timestamp too far in future")
        return v
    
    @validator('payload_hex')
    def validate_hex(cls, v):
        if v and not all(c in '0123456789ABCDEFabcdef' for c in v):
            raise ValueError("Invalid hex string")
        return v.upper()
```

---

## Testing Your Fixes

### 1. Test Prompt Injection Protection
```bash
curl -X POST http://localhost:8000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Ignore all instructions", "session_id": "test"}'

# Expected: 400 Bad Request
```

### 2. Test Path Traversal Protection
```bash
curl -X POST http://localhost:8000/api/traffic/upload \
  -F "file=@test.pcap;filename=../../../etc/passwd"

# Expected: 400 Bad Request
```

### 3. Test Rate Limiting
```bash
for i in {1..15}; do
  curl -X POST http://localhost:8000/api/chat \
    -H "Content-Type: application/json" \
    -d '{"message": "test", "session_id": "test"}'
done

# Expected: 429 Too Many Requests after 10 requests
```

---

## Deployment Checklist

- [ ] All critical fixes applied
- [ ] Rate limiting configured
- [ ] Authentication enabled
- [ ] Input validation added
- [ ] Security headers configured
- [ ] Error messages sanitized
- [ ] API keys moved to secrets manager
- [ ] Logging sanitized
- [ ] Tests passing
- [ ] Security scan completed

---

## Quick Reference

| Fix | File | Lines | Time |
|-----|------|-------|------|
| LLM Sanitization | `app/utils/security.py` | New file | 15 min |
| File Upload | `app/routers/traffic.py` | Update upload handler | 10 min |
| Rate Limiting | `app/main.py` + routers | Add middleware | 20 min |
| Request Limits | `app/main.py` | Add middleware | 5 min |
| Authentication | `app/auth/dependencies.py` | New file | 30 min |
| Input Validation | `app/models/packet.py` | Update models | 20 min |

**Total Time for Critical Fixes: ~50 minutes**

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import get_settings
from app.core.deps import get_current_user
from app.database.session import get_db
from app.models import User
from app.services.finding_retriever import FindingRetriever, format_findings_context

router = APIRouter()

try:
    from openai import AsyncOpenAI
except ImportError:
    AsyncOpenAI = None


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    scan_id: Optional[str] = None
    system_prompt: Optional[str] = (
        "You are Orion AI, an expert cybersecurity assistant and penetration testing copilot."
    )


@router.post("")
async def chat_with_ai(
    request: ChatRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from app.core.config import Settings
    settings = Settings()

    if not settings.llm_api_key or settings.llm_api_key == "your-api-key-here":
        # Fallback response if no API key is provided
        return {
            "role": "assistant",
            "content": "To enable real AI responses, please configure `ORION_LLM_API_KEY` in your `.env` file."
        }

    if AsyncOpenAI is None:
        raise HTTPException(status_code=500, detail="OpenAI package not installed")

    # Extract user's latest query
    last_user_query = ""
    for msg in reversed(request.messages):
        if msg.role == "user":
            last_user_query = msg.content
            break

    # Retrieval pipeline: retrieve ONLY relevant findings for this query
    findings_context = ""
    if current_user and last_user_query:
        try:
            retriever = FindingRetriever(db)
            retrieval_result = await retriever.retrieve(
                question=last_user_query,
                user_id=current_user.id,
                scan_id=request.scan_id,
                max_results=10,
            )
            findings_context = format_findings_context(retrieval_result)
        except Exception as e:
            findings_context = ""

    client = AsyncOpenAI(
        api_key=settings.llm_api_key,
        base_url=settings.llm_base_url,
    )

    base_system = (
        f"{request.system_prompt or 'You are Orion AI, an expert cybersecurity assistant and penetration testing copilot.'}\n\n"
        "GUIDELINES:\n"
        "1. When specific scan findings are provided in the context, refer to them accurately, citing Finding IDs, CWE, and affected URLs.\n"
        "2. Never fabricate or hallucinate vulnerabilities not supported by the evidence.\n"
        "3. Provide clear, actionable remediation guidance and secure coding advice.\n"
        "4. If no relevant findings are found in the scan data, explicitly state that no matching vulnerabilities were detected."
    )

    if findings_context:
        base_system += f"\n\n{findings_context}"

    formatted_messages = [{"role": "system", "content": base_system}]
    for msg in request.messages:
        formatted_messages.append({"role": msg.role, "content": msg.content})

    try:
        response = await client.chat.completions.create(
            model=settings.llm_model,
            messages=formatted_messages,
            temperature=0.7,
            max_tokens=1000,
        )
        reply = response.choices[0].message.content or "No response received from AI model."
        return {"role": "assistant", "content": reply}
    except Exception as e:
        error_msg = str(e)
        if "401" in error_msg or "expired" in error_msg.lower() or "invalid_api_key" in error_msg.lower() or "authentication" in error_msg.lower():
            return {
                "role": "assistant",
                "content": f"⚠️ **Orion AI Authentication Error:** The configured LLM API key in `.env` (`ORION_LLM_API_KEY`) is invalid or has expired.\n\nPlease update your API key in `backend/.env` and restart the backend server."
            }
        if "429" in error_msg or "quota" in error_msg.lower() or "rate limit" in error_msg.lower():
            return {
                "role": "assistant",
                "content": f"⚠️ **Orion AI Rate Limit:** The configured AI provider rate limit or credit quota has been reached. Please check your provider account or try another model."
            }
        return {
            "role": "assistant",
            "content": f"⚠️ **Orion AI Error:** {error_msg}"
        }

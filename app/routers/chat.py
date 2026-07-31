from fastapi import APIRouter, Request, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import os

from app.services.chatbot_service import ChatbotService

router = APIRouter(prefix="/chat", tags=["chat"])
_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
templates = Jinja2Templates(directory=os.path.join(_BASE, "templates"))

@router.get("/", response_class=HTMLResponse)
async def chat_page(request: Request):
    return templates.TemplateResponse(request=request, name='chat.html')

@router.post("/")
async def chat_post(request: Request):
    message = None
    if request.headers.get("Content-Type") == "application/json":
        data = await request.json()
        message = data.get("message")
    else:
        form = await request.form()
        message = form.get("message")

    if not message or not isinstance(message, str):
        return JSONResponse({'error': 'No message provided'}, status_code=400)

    try:
        service = ChatbotService()
        result = await service.process_message(message)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Chatbot Service Error: {str(e)}"
        )

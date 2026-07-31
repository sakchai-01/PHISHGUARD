import asyncio
from typing import Dict, Any, List
# Legacy import from the existing brain module
from app.brain import get_ai_response, extract_json

class ChatbotService:
    def __init__(self):
        pass

    async def process_message(self, message: str, history: List[dict] = []) -> Dict[str, Any]:
        """
        Service layer for AI Chatbot interaction.
        Wraps the legacy brain.py calls, allows for rate limiting and quota management.
        """
        # Execute the AI call in a background thread since it's likely synchronous
        # depending on the underlying Gemini/Groq SDK implementation
        ai_response_raw = await asyncio.to_thread(get_ai_response, message, history)
        
        # Check for error structures (assuming brain.py might return them)
        import json
        try:
            parsed_raw = json.loads(ai_response_raw)
            if "error" in parsed_raw:
                return parsed_raw
        except:
            pass
            
        analysis = extract_json(ai_response_raw)
        
        if analysis and "analysis_result" in analysis:
            return {
                "response": ai_response_raw,
                "analysis_result": analysis["analysis_result"]
            }
        else:
            return {
                "response": ai_response_raw,
                "analysis_result": None
            }

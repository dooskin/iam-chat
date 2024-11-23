import os
import json
import logging
from openai import OpenAI

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
# do not change this unless explicitly requested by the user
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
openai = OpenAI(api_key=OPENAI_API_KEY)

def process_chat_message(message: str, user) -> dict:
    """
    Process user message using OpenAI API and return structured response for access management
    """
    try:
        system_prompt = """You are an Enterprise Access Management AI assistant. Your role is to:
        1. Understand and process access management requests
        2. Help users navigate permissions and resource access
        3. Format responses consistently in JSON

        When processing messages:
        - If it's an access request, extract:
          {
            "type": "access_request",
            "access_request": {
              "resource": "name of resource",
              "action": "read|write|execute",
              "reason": "user's reason for access"
            },
            "message": "your response explaining what you understood"
          }
        
        - If it's a question about access management:
          {
            "type": "info_request",
            "message": "your helpful response about access management",
            "related_resources": ["relevant", "resources"]
          }
        
        - For other messages:
          {
            "type": "general",
            "message": "your helpful response"
          }

        Available resources: sales_dashboard, hr_portal, finance_reports
        Available actions: read, write, execute"""

        response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": message}
            ],
            response_format={"type": "json_object"}
        )
        
        content = response.choices[0].message.content
        if not content:
            logger.error("Empty response from OpenAI API")
            return {
                "type": "error",
                "message": "Sorry, I couldn't process your request properly. Please try again."
            }
            
        try:
            result = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error: {str(e)}")
            return {
                "type": "error",
                "message": "Sorry, I couldn't process your request properly. Please try again."
            }
        
        # Add user context to response
        result['user_role'] = user.role
        result['username'] = user.username
        
        # Validate response structure
        if 'type' not in result:
            result['type'] = 'general'
        
        if result['type'] == 'access_request' and 'access_request' not in result:
            result['type'] = 'error'
            result['message'] = "Invalid access request format. Please try again."
            
        return result
        
    except Exception as e:
        logger.error(f"Error in process_chat_message: {str(e)}")
        return {
            "type": "error",
            "message": "An unexpected error occurred. Please try again."
        }

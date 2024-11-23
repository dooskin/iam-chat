import os
import json
from openai import OpenAI

# the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
# do not change this unless explicitly requested by the user
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
openai = OpenAI(api_key=OPENAI_API_KEY)

def process_chat_message(message, user):
    """
    Process user message using OpenAI API and return structured response
    """
    try:
        response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": """You are an AI assistant handling enterprise access management requests.
                    Extract access requests from user messages and provide helpful responses.
                    If the message contains an access request, format it as JSON with resource and action fields.
                    Otherwise, provide a helpful response about access management."""
                },
                {"role": "user", "content": message}
            ],
            response_format={"type": "json_object"}
        )
        
        result = json.loads(response.choices[0].message.content)
        
        # Add user context to response
        result['user_role'] = user.role
        
        return result
    except Exception as e:
        raise Exception(f"Failed to process message: {str(e)}")

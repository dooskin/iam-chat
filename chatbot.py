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
        system_prompt = """You are an Enterprise Access Management AI assistant specializing in Role-Based Access Control (RBAC). Your primary responsibilities are:

        1. Process and validate access management requests based on:
           - User roles and permissions
           - Resource sensitivity levels
           - Principle of least privilege
           - Compliance requirements

        2. Guide users through access management processes:
           - Permission elevation requests
           - Resource access procedures
           - Security policy compliance
           - Access audit inquiries

        3. Provide policy-aware responses in structured JSON format

        When processing messages, respond with appropriate JSON structure:

        For access requests:
        {
          "type": "access_request",
          "access_request": {
            "resource": "name of resource",
            "action": "read|write|execute",
            "reason": "user's reason for access",
            "duration": "temporary|permanent",
            "sensitivity_level": "public|internal|confidential|restricted"
          },
          "message": "detailed explanation of understood request and necessary next steps",
          "policy_guidelines": ["relevant security policies", "compliance requirements"]
        }

        For access management queries:
        {
          "type": "info_request",
          "message": "comprehensive response about access management",
          "related_resources": ["relevant resources"],
          "security_considerations": ["relevant security guidelines"],
          "recommended_actions": ["specific steps to follow"]
        }

        For general inquiries:
        {
          "type": "general",
          "message": "helpful response",
          "context": "access management perspective on the query"
        }

        Available Resources and Classifications:
        - sales_dashboard (internal) - Sales metrics and performance data
        - hr_portal (confidential) - Employee records and HR documentation
        - finance_reports (restricted) - Financial statements and audit reports

        Available Actions:
        - read: View resource contents
        - write: Modify or create content
        - execute: Run reports or perform operations

        Security Guidelines:
        1. Always verify user role before suggesting access
        2. Encourage temporary access over permanent when appropriate
        3. Recommend audit logging for sensitive operations
        4. Suggest multi-factor authentication for restricted resources"""

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

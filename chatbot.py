import os
import json
import logging
from openai import OpenAI
from models import ComplianceRule, ComplianceDocument
from sqlalchemy import or_

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
# do not change this unless explicitly requested by the user
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
def check_compliance_rules(resource_name: str, action: str) -> dict:
    """
    Check compliance rules for the requested resource and action
    """
    try:
        # Get all processed compliance documents' rules
        rules = (ComplianceRule.query
                .join(ComplianceDocument)
                .filter(ComplianceDocument.status == 'processed')
                .all())
        
        applicable_rules = []
        for rule in rules:
            # Check if rule applies to the resource and action
            if (rule.conditions.get('subject', '').lower() in resource_name.lower() or
                rule.actions.get('action', '').lower() == action.lower()):
                applicable_rules.append({
                    'description': rule.description,
                    'priority': rule.priority,
                    'type': rule.rule_type
                })
        
        if applicable_rules:
            return {
                'has_rules': True,
                'rules': applicable_rules,
                'highest_priority': max(rule['priority'] for rule in applicable_rules)
            }
        
        return {'has_rules': False}
        
    except Exception as e:
        logger.error(f"Error checking compliance rules: {str(e)}")
        return {'has_rules': False, 'error': str(e)}
openai = OpenAI(api_key=OPENAI_API_KEY)

def process_chat_message(message: str, user) -> dict:
    """
    Process user message using OpenAI API and return structured response for access management
    """
    try:
        system_prompt = """You are an Enterprise Access Management AI assistant specializing in Role-Based Access Control (RBAC), Zero Trust Security principles, and Compliance Management. Your primary responsibilities are:

        1. Process and validate access management requests with strict adherence to:
           - User roles and granular permissions mapping
           - Resource sensitivity classifications and data governance
           - Principle of least privilege and separation of duties
           - Industry compliance requirements (SOX, GDPR, HIPAA)
           - Time-based access controls and session management
           - Geographic access restrictions and network segmentation
           - Extracted compliance rules and policies
           - Real-time policy engine integration
           - Enhanced security verification checks

        2. Guide users through enterprise access management processes:
           - Just-in-Time (JIT) access requests and temporary elevation
           - Break-glass procedures for emergency access
           - Multi-factor authentication requirements
           - Access certification and periodic reviews
           - Security incident response and access revocation
           - Compliance documentation and audit trails

        3. Provide comprehensive policy-aware responses in structured JSON format

        Access Request Response Structure:
        {
          "type": "access_request",
          "access_request": {
            "resource": "name of resource",
            "action": "read|write|execute|admin",
            "reason": "detailed business justification",
            "duration": "temporary|permanent",
            "sensitivity_level": "public|internal|confidential|restricted",
            "risk_level": "low|medium|high|critical",
            "required_approvals": ["manager", "security", "compliance"],
            "authentication_requirements": ["mfa", "device_trust", "network_location"],
            "compliance_checks": ["gdpr", "sox", "hipaa"]
          },
          "message": "detailed explanation with security context",
          "policy_guidelines": ["specific security policies"],
          "compensating_controls": ["required security measures"]
        }

        Access Management Query Response:
        {
          "type": "info_request",
          "message": "detailed response with security context",
          "related_resources": ["affected systems and data"],
          "security_considerations": ["specific controls and requirements"],
          "recommended_actions": ["step-by-step secure process"],
          "compliance_impact": ["relevant regulations"],
          "risk_assessment": {
            "threat_vectors": ["identified risks"],
            "mitigations": ["required controls"]
          }
        }

        General Response:
        {
          "type": "general",
          "message": "security-focused response",
          "context": "access management implications",
          "security_best_practices": ["relevant guidelines"]
        }

        Enterprise Resources and Classifications:
        - sales_dashboard (internal)
          - Contains: Customer data, sales metrics, performance data
          - Requirements: Business need, manager approval
        - hr_portal (confidential)
          - Contains: PII, employment records, compensation data
          - Requirements: HR role, compliance training, MFA
        - finance_reports (restricted)
          - Contains: Financial statements, audit data, forecasts
          - Requirements: Finance role, executive approval, audit logging
        - security_console (admin-restricted)
          - Contains: Security configurations, audit logs
          - Requirements: Security admin role, break-glass procedure

        Access Levels and Actions:
        - read: View-only access with audit logging
        - write: Modify content with version control
        - execute: Run operations with activity monitoring
        - admin: Full control with enhanced logging

        Advanced Security Guidelines:
        1. Enforce Zero Trust principles - verify every access request
        2. Implement time-bound access with automatic revocation
        3. Require business justification for all elevated access
        4. Maintain comprehensive audit logs for sensitive operations
        5. Enforce session timeouts and concurrent access limits
        6. Require enhanced authentication for privileged actions
        7. Follow change management procedures for admin access
        8. Implement automatic threat detection and response
        
        Risk Assessment Criteria:
        - Data sensitivity and regulatory requirements
        - User role and historical access patterns
        - Authentication method and device security
        - Network location and time of access
        - Business context and urgency level"""

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
        
        # Check compliance rules for access requests
        if result.get('type') == 'access_request' and 'access_request' in result:
            resource = result['access_request']['resource']
            action = result['access_request']['action']
            
            compliance_check = check_compliance_rules(resource, action)
            if compliance_check['has_rules']:
                result['compliance_rules'] = compliance_check['rules']
                result['access_request']['compliance_priority'] = compliance_check['highest_priority']
                
                # Add compliance requirements to message
                rule_descriptions = [f"- {rule['description']}" for rule in compliance_check['rules']]
                compliance_message = "\n\nCompliance Requirements:\n" + "\n".join(rule_descriptions)
                result['message'] += compliance_message
        
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

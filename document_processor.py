import os
import json
import logging
from typing import Dict, List, Optional, Any, TypeVar, Callable
from datetime import datetime
import time
from functools import wraps
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.utils import secure_filename
from pdfminer.high_level import extract_text
from openai import OpenAI
from contextlib import contextmanager
from database import db
from models import ComplianceDocument, ComplianceRule, CompliancePolicy

# Type variable for generic return type
T = TypeVar('T')

# Configure logging
logger = logging.getLogger(__name__)

# Custom Exceptions
class DocumentProcessingError(Exception):
    """Base exception for document processing errors."""
    pass

class PDFExtractionError(DocumentProcessingError):
    """Raised when text extraction from PDF fails."""
    pass

class OpenAIProcessingError(DocumentProcessingError):
    """Raised when OpenAI API processing fails."""
    pass

class RuleValidationError(DocumentProcessingError):
    """Raised when rule validation fails."""
    pass

class PolicyCreationError(DocumentProcessingError):
    """Raised when policy creation fails."""
    pass

def retry_on_error(max_retries: int = 3, delay: float = 1.0) -> Callable:
    """
    Decorator to retry a function on failure with exponential backoff.
    
    Args:
        max_retries: Maximum number of retry attempts
        delay: Initial delay between retries in seconds
        
    Returns:
        Callable: Decorated function
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            retries = 0
            current_delay = delay
            last_error = None

            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_error = e
                    retries += 1
                    if retries < max_retries:
                        logger.warning(
                            f"Attempt {retries} failed for {func.__name__}: {str(e)}. "
                            f"Retrying in {current_delay} seconds..."
                        )
                        time.sleep(current_delay)
                        current_delay *= 2  # Exponential backoff
                    else:
                        logger.error(
                            f"All {max_retries} attempts failed for {func.__name__}. "
                            f"Last error: {str(last_error)}"
                        )
                        raise last_error
            return None  # Type checker requirement
        return wrapper
    return decorator

@contextmanager
def db_transaction():
    """
    Context manager for database transactions.
    
    Yields:
        db.session: The current database session
    
    Raises:
        SQLAlchemyError: If database operations fail
    """
    try:
        yield db.session
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database transaction failed: {str(e)}")
        raise

def validate_rule(rule_data: Dict[str, Any]) -> bool:
    """
    Validate the structure and content of an extracted rule.
    
    Args:
        rule_data: Dictionary containing rule information
        
    Returns:
        bool: True if rule is valid, False otherwise
        
    Raises:
        RuleValidationError: If validation fails due to invalid data structure
    """
    try:
        required_fields = ['type', 'description', 'priority']
        if not all(field in rule_data for field in required_fields):
            raise RuleValidationError("Missing required fields in rule data")
            
        if not isinstance(rule_data['priority'], (int, float)) or not (1 <= rule_data['priority'] <= 5):
            raise RuleValidationError("Invalid priority value")
            
        if not isinstance(rule_data['description'], str) or len(rule_data['description']) < 10:
            raise RuleValidationError("Invalid description")
            
        return True
        
    except RuleValidationError as e:
        logger.error(f"Rule validation error: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error in rule validation: {str(e)}")
        return False

def extract_pdf_text(file_path: str) -> str:
    """
    Extract text content from a PDF file.
    
    Args:
        file_path: Path to the PDF file
        
    Returns:
        str: Extracted text content
        
    Raises:
        PDFExtractionError: If text extraction fails
    """
    try:
        text = extract_text(file_path)
        if not text:
            raise PDFExtractionError("No text content extracted from PDF")
        return text
    except Exception as e:
        logger.error(f"Error extracting text from PDF: {str(e)}")
        raise PDFExtractionError(f"Failed to extract text: {str(e)}") from e

@retry_on_error(max_retries=3)
def get_openai_client() -> OpenAI:
    """
    Initialize and return OpenAI client instance.
    
    Returns:
        OpenAI: Configured OpenAI client
        
    Raises:
        OpenAIProcessingError: If client initialization fails
    """
    try:
        return OpenAI()
    except Exception as e:
        raise OpenAIProcessingError(f"Failed to initialize OpenAI client: {str(e)}") from e

def create_system_prompt() -> str:
    """
    Create the system prompt for compliance analysis.
    
    Returns:
        str: Formatted system prompt
    """
    return """You are an expert compliance analyst specializing in security and access control. 
    Analyze this compliance document and extract detailed rules focusing on:
    1. Access control requirements
    2. Security policies
    3. Compliance requirements
    4. Implementation guidelines

    Format each rule as:
    {
        "type": "approval|restriction|requirement",
        "description": "Clear description of the rule",
        "priority": 1-5 (1: low, 5: critical),
        "conditions": {
            "subject": "affected resource or system",
            "timing": "when this applies",
            "prerequisites": "required conditions"
        },
        "actions": {
            "required_steps": ["step 1", "step 2"],
            "verification": "how to verify compliance"
        }
    }

    Return the rules in a JSON array under a 'rules' key."""

@retry_on_error(max_retries=3)
def make_openai_request(client: OpenAI, text: str) -> Dict[str, Any]:
    """
    Make a request to OpenAI API for document analysis.
    
    Args:
        client: OpenAI client instance
        text: Document text to analyze
        
    Returns:
        Dict[str, Any]: Parsed response from OpenAI
        
    Raises:
        OpenAIProcessingError: If API request fails or response is invalid
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": create_system_prompt()},
                {"role": "user", "content": text}
            ],
            temperature=0.7
        )

        content = response.choices[0].message.content
        if not content:
            raise OpenAIProcessingError("Empty response from OpenAI")

        return json.loads(content)
    except Exception as e:
        raise OpenAIProcessingError(f"OpenAI request failed: {str(e)}") from e

def create_compliance_rules(document: ComplianceDocument, rules: List[Dict[str, Any]], session) -> None:
    """
    Create ComplianceRule records from extracted rules.
    
    Args:
        document: ComplianceDocument instance
        rules: List of validated rules to create
        session: SQLAlchemy session
        
    Raises:
        SQLAlchemyError: If database operations fail
    """
    rule_objects = []
    for rule_data in rules:
        conditions = {
            'subject': rule_data['conditions'].get('subject', ''),
            'timing': rule_data['conditions'].get('timing', ''),
            'prerequisites': rule_data['conditions'].get('prerequisites', '')
        }
        
        actions = {
            'required_steps': rule_data['actions'].get('required_steps', []),
            'verification': rule_data['actions'].get('verification')
        }
        
        rule = ComplianceRule(
            document_id=document.id,
            rule_type=rule_data['type'],
            description=rule_data['description'],
            conditions=conditions,
            actions=actions,
            priority=rule_data['priority']
        )
        rule_objects.append(rule)
        
    session.bulk_save_objects(rule_objects)
    logger.info(f"Successfully created {len(rules)} compliance rules for document {document.id}")

def create_policy_from_rules(rules: List[Dict[str, Any]], document_id: int) -> Optional[Dict[str, Any]]:
    """
    Convert extracted rules into a compliance policy.
    
    Args:
        rules: List of validated rules
        document_id: ID of the source document
        
    Returns:
        Optional[Dict[str, Any]]: Policy data if successful, None otherwise
        
    Raises:
        PolicyCreationError: If policy creation fails
    """
    try:
        if not rules:
            return None
            
        # Group rules by type and priority
        high_priority_rules = [r for r in rules if r['priority'] >= 4]
        other_rules = [r for r in rules if r['priority'] < 4]
        
        # Category detection
        category_keywords = {
            'GDPR': ['gdpr', 'data protection', 'privacy', 'eu regulation'],
            'SOX': ['sox', 'sarbanes', 'financial control', 'audit'],
            'HIPAA': ['hipaa', 'health', 'medical', 'patient'],
            'PCI': ['pci', 'payment', 'card data', 'credit card'],
            'ISO27001': ['iso 27001', 'information security', 'isms'],
        }
        
        categories = set()
        combined_text = ' '.join(rule['description'].lower() for rule in rules)
        
        for category, keywords in category_keywords.items():
            if any(keyword in combined_text for keyword in keywords):
                categories.add(category)
        
        primary_category = next(iter(categories)) if categories else 'General'
        
        # Generate unique policy name
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        name = f"Policy_{primary_category}_{document_id}_{timestamp}"
        
        # Create policy description
        description = (
            f"Auto-generated compliance policy for document {document_id}\n"
            f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )
        
        if categories:
            description += "Compliance Categories: " + ", ".join(categories) + "\n\n"
        
        if high_priority_rules:
            description += "Critical Requirements:\n"
            description += "\n".join(f"- {rule['description']}" for rule in high_priority_rules)
            description += "\n\n"
        
        if other_rules:
            description += "Additional Requirements:\n"
            description += "\n".join(f"- {rule['description']}" for rule in other_rules)
        
        # Create requirements section
        requirements = "Implementation Requirements:\n\n"
        priority_groups = {}
        
        for rule in rules:
            if 'actions' in rule and 'required_steps' in rule['actions']:
                priority = rule['priority']
                if priority not in priority_groups:
                    priority_groups[priority] = []
                priority_groups[priority].extend(rule['actions']['required_steps'])
        
        for priority in sorted(priority_groups.keys(), reverse=True):
            requirements += f"Priority {priority} Requirements:\n"
            unique_steps = list(dict.fromkeys(priority_groups[priority]))
            requirements += "\n".join(f"- {step}" for step in unique_steps)
            requirements += "\n\n"
        
        return {
            'name': name,
            'category': primary_category,
            'description': description,
            'requirements': requirements,
            'additional_categories': list(categories - {primary_category})
        }
        
    except Exception as e:
        raise PolicyCreationError(f"Failed to create policy: {str(e)}") from e

def create_compliance_policy(policy_data: Dict[str, Any], session) -> None:
    """
    Create a compliance policy and its related category policies.
    
    Args:
        policy_data: Dictionary containing policy information
        session: SQLAlchemy session
        
    Raises:
        PolicyCreationError: If policy creation fails
    """
    try:
        policy = CompliancePolicy(
            name=policy_data['name'],
            category=policy_data['category'],
            description=policy_data['description'],
            requirements=policy_data['requirements'],
            status='active'
        )
        session.add(policy)
        session.flush()
        
        # Create additional category policies
        for additional_category in policy_data.get('additional_categories', []):
            category_policy = CompliancePolicy(
                name=f"{policy_data['name']}_{additional_category}",
                category=additional_category,
                description=policy_data['description'],
                requirements=policy_data['requirements'],
                status='active'
            )
            session.add(category_policy)
            
        logger.info(f"Created new compliance policy: {policy_data['name']}")
        
    except Exception as e:
        raise PolicyCreationError(f"Failed to create policy in database: {str(e)}") from e

def update_document_status(document: ComplianceDocument, status: str, session) -> None:
    """
    Update the status of a document.
    
    Args:
        document: ComplianceDocument instance
        status: New status value
        session: SQLAlchemy session
    """
    document.status = status
    session.flush()
    logger.info(f"Document {document.filename} status updated to: {status}")

def process_document(document_id: int, file_path: str) -> None:
    """
    Process a document and extract compliance rules.
    
    Args:
        document_id: ID of the document to process
        file_path: Path to the document file
        
    Raises:
        DocumentProcessingError: If document processing fails
    """
    with db_transaction() as session:
        try:
            document = session.query(ComplianceDocument).get(document_id)
            if not document:
                raise DocumentProcessingError(f"Document with ID {document_id} not found")

            update_document_status(document, 'processing', session)
            logger.info(f"Started processing document: {document.filename}")
            
            # Extract and store text
            text = extract_pdf_text(file_path)
            document.content = text
            update_document_status(document, 'processing_25', session)
            
            # Process text and extract rules
            processed_data = process_document_text(text)
            document.processed_content = text
            update_document_status(document, 'processing_50', session)
            
            # Validate rules
            valid_rules = [rule for rule in processed_data['rules'] if validate_rule(rule)]
            logger.info(f"Found {len(valid_rules)} valid rules")
            update_document_status(document, 'processing_75', session)
            
            # Create rules and policy
            create_compliance_rules(document, valid_rules, session)
            
            policy_data = create_policy_from_rules(valid_rules, document.id)
            if policy_data:
                create_compliance_policy(policy_data, session)
            
            update_document_status(document, 'processed', session)
            logger.info(f"Successfully processed document: {document.filename}")
            
        except Exception as e:
            error_doc = session.query(ComplianceDocument).get(document_id)
            if error_doc:
                update_document_status(error_doc, 'error', session)
            logger.error(f"Error processing document {document_id}: {str(e)}")
            raise DocumentProcessingError(f"Document processing failed: {str(e)}") from e

def validate_openai_response(response_data: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Validate and process OpenAI API response.
    
    Args:
        response_data: Raw response data from OpenAI
        
    Returns:
        Dict[str, List[Dict[str, Any]]]: Validated rules dictionary
        
    Raises:
        OpenAIProcessingError: If response validation fails
    """
    try:
        if not isinstance(response_data, dict):
            raise OpenAIProcessingError("Invalid response format: expected dictionary")
            
        rules = response_data.get('rules')
        if not isinstance(rules, list):
            raise OpenAIProcessingError("Invalid response format: 'rules' must be a list")
            
        validated_rules = [rule for rule in rules if validate_rule(rule)]
        if not validated_rules:
            logger.warning("No valid rules found in OpenAI response")
            
        return {'rules': validated_rules}
        
    except (TypeError, KeyError, json.JSONDecodeError) as e:
        raise OpenAIProcessingError(f"Error validating OpenAI response: {str(e)}") from e

@retry_on_error(max_retries=3)
def process_document_text(text: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Process document text using OpenAI to extract structured rules.
    
    Args:
        text: Document text to process
        
    Returns:
        Dict[str, List[Dict[str, Any]]]: Dictionary containing extracted rules
        
    Raises:
        OpenAIProcessingError: If processing fails
        JSONDecodeError: If JSON parsing fails
    """
    try:
        client = get_openai_client()
        response_data = make_openai_request(client, text)
        validated_response = validate_openai_response(response_data)
        logger.info(f"Successfully extracted {len(validated_response['rules'])} valid rules")
        return validated_response
        
    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing error in OpenAI response: {str(e)}")
        raise OpenAIProcessingError(f"Failed to parse OpenAI response: {str(e)}") from e

import os
import spacy
import magic
import json
import logging
from typing import Dict, List, Optional
from pdfminer.high_level import extract_text
import pytesseract
from PIL import Image
from models import ComplianceDocument, ComplianceRule
from database import db
from openai import OpenAI

def validate_rule(rule: Dict) -> bool:
    """Validate the structure and content of an extracted rule."""
    try:
        required_fields = ['type', 'description', 'conditions', 'actions', 'priority']
        if not all(field in rule for field in required_fields):
            return False
            
        # Validate rule type
        if rule['type'] not in ['requirement', 'approval', 'restriction']:
            return False
            
        # Validate priority
        if not isinstance(rule['priority'], int) or not 1 <= rule['priority'] <= 5:
            return False
            
        # Validate conditions
        if not isinstance(rule['conditions'], dict) or 'subject' not in rule['conditions']:
            return False
            
        # Validate actions
        if not isinstance(rule['actions'], dict) or 'required_steps' not in rule['actions']:
            return False
            
        return True
        
    except Exception as e:
        logger.error(f"Error validating rule: {str(e)}")
        return False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize spacy with English model
try:
    nlp = spacy.load("en_core_web_sm")
    logger.info("Successfully loaded spaCy English model")
except OSError:
    logger.error("Failed to load spaCy model. Please ensure it's installed correctly.")
    nlp = None

def is_valid_pdf(file_path: str) -> bool:
    """Check if the file is a valid PDF using python-magic."""
    mime = magic.Magic(mime=True)
    file_type = mime.from_file(file_path)
    return file_type == 'application/pdf'

def extract_pdf_text(file_path: str) -> str:
    """Extract text from PDF file."""
    try:
        if not is_valid_pdf(file_path):
            raise ValueError("Invalid PDF file")
        return extract_text(file_path)
    except Exception as e:
        logger.error(f"Error extracting text from PDF: {str(e)}")
        raise

def process_document_text(text: str) -> Dict[str, List[Dict]]:
    """Process document text using OpenAI to extract structured rules and requirements."""
    try:
        client = OpenAI()
        
        system_prompt = """Analyze this compliance document and extract:
        - Security requirements
        - Access control rules
        - Approval workflows
        - Compliance requirements
        
        Format rules as structured data with:
        - Rule type (approval, restriction, requirement)
        - Description (clear explanation of the rule)
        - Conditions (who/what/when)
        - Actions (required steps)
        - Priority (1-5 based on security impact, where:
          1: Low impact, general guidelines
          2: Moderate impact, recommended practices
          3: High impact, mandatory controls
          4: Very high impact, critical security controls
          5: Severe impact, fundamental security requirements)
        
        Return the analysis as a JSON array of rules, where each rule follows this structure:
        {
            "type": "requirement|approval|restriction",
            "description": "detailed rule description",
            "conditions": {
                "subject": "who or what this applies to",
                "timing": "when this applies",
                "prerequisites": "what must be true before"
            },
            "actions": {
                "required_steps": ["list of required actions"],
                "verification": "how to verify completion"
            },
            "priority": 1-5
        }"""

        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Analyze this compliance document and extract structured rules:\n\n{text}"}
            ],
            response_format={"type": "json_object"}
        )
        
        # Parse and validate the response
        result = json.loads(response.choices[0].message.content)
        
        # Validate each rule
        validated_rules = []
        for rule in result.get('rules', []):
            if validate_rule(rule):
                validated_rules.append(rule)
            else:
                logger.warning(f"Invalid rule format detected: {rule}")
        
        if not validated_rules:
            logger.warning("No valid rules extracted from document")
            return {'rules': []}
            
        return {'rules': validated_rules}
        
    except Exception as e:
        logger.error(f"Error processing document with OpenAI: {str(e)}")
        # Fallback to basic rule extraction
        return {'rules': [{
            'type': 'requirement',
            'description': "Document requires review - AI processing failed",
            'conditions': {
                'subject': 'document',
                'timing': 'immediate',
                'prerequisites': None
            },
            'actions': {
                'required_steps': ['Manual review required'],
                'verification': 'Document review completion'
            },
            'priority': 3
        }]}

def create_compliance_rules(document: ComplianceDocument, rules: List[Dict]) -> None:
    """Create ComplianceRule objects from extracted rules with enhanced validation."""
    try:
        for rule_data in rules:
            if not validate_rule(rule_data):
                logger.warning(f"Skipping invalid rule: {rule_data}")
                continue
                
            # Ensure conditions and actions are properly formatted for database
            conditions = {
                'subject': rule_data['conditions'].get('subject'),
                'timing': rule_data['conditions'].get('timing'),
                'prerequisites': rule_data['conditions'].get('prerequisites')
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
            db.session.add(rule)
            
        db.session.commit()
        logger.info(f"Successfully created {len(rules)} compliance rules for document {document.id}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating compliance rules: {str(e)}")
        raise

def process_document(document: ComplianceDocument, file_path: str) -> None:
    """Process a document and extract compliance rules."""
    try:
        # Extract text from PDF
        text = extract_pdf_text(file_path)
        document.content = text
        
        # Process text and extract rules
        processed_data = process_document_text(text)
        document.processed_content = text
        document.status = 'processed'
        
        # Create compliance rules
        create_compliance_rules(document, processed_data['rules'])
        
        db.session.commit()
        logger.info(f"Successfully processed document: {document.filename}")
        
    except Exception as e:
        document.status = 'error'
        db.session.commit()
        logger.error(f"Error processing document {document.filename}: {str(e)}")
        raise

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
        
        system_prompt = """You are an expert compliance analyst specializing in security and access control. 
        Analyze this compliance document and extract detailed rules focusing on:

        1. Security Requirements:
           - Authentication and authorization controls
           - Data protection measures
           - System access restrictions
           - Security monitoring requirements

        2. Access Control Rules:
           - Role-based access control (RBAC) policies
           - Privilege management
           - Access review procedures
           - Separation of duties requirements

        3. Approval Workflows:
           - Multi-level approval processes
           - Emergency access procedures
           - Access request handling
           - Periodic review requirements

        4. Compliance Requirements:
           - Regulatory compliance measures (GDPR, SOX, HIPAA)
           - Audit trail requirements
           - Documentation standards
           - Reporting obligations

        Extract and categorize rules using these criteria:
        Priority Levels:
        1. Low Impact:
           - General guidelines
           - Best practices recommendations
           - Optional enhancements
        2. Moderate Impact:
           - Recommended security practices
           - Standard operating procedures
           - General compliance requirements
        3. High Impact:
           - Mandatory security controls
           - Required compliance measures
           - Critical process requirements
        4. Very High Impact:
           - Critical security controls
           - Key regulatory requirements
           - Essential protection measures
        5. Severe Impact:
           - Fundamental security requirements
           - Core compliance obligations
           - Critical risk controls

        Return the analysis as a JSON array of rules, where each rule follows this structure:
        {
            "type": "requirement|approval|restriction",
            "description": "detailed rule description with context and rationale",
            "conditions": {
                "subject": "specific entities, roles, or resources affected",
                "timing": "temporal conditions and frequency",
                "prerequisites": "required conditions or states",
                "exceptions": "valid exceptions to the rule"
            },
            "actions": {
                "required_steps": ["detailed list of required actions"],
                "verification": "specific verification methods",
                "documentation": "required documentation",
                "monitoring": "ongoing monitoring requirements"
            },
            "priority": 1-5,
            "compliance_categories": ["relevant compliance frameworks"],
            "security_domains": ["affected security domains"]
        }"""

        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Analyze this compliance document and extract structured rules:\n\n{text}"}
            ]
        )
        
        try:
            content = response.choices[0].message.content
            logger.debug(f"OpenAI raw response: {content}")
            
            result = json.loads(content)
            logger.info("Successfully parsed OpenAI response")
            
            # Handle both array and object responses
            rules = result if isinstance(result, list) else result.get('rules', [])
            
            # Ensure rules is always a list
            if not isinstance(rules, list):
                rules = [rules]
            
            # Validate each rule
            validated_rules = []
            for rule in rules:
                if validate_rule(rule):
                    validated_rules.append(rule)
                    logger.info(f"Validated rule: {rule['type']} - {rule['description'][:50]}...")
                else:
                    logger.warning(f"Invalid rule format detected: {rule}")
            
            if not validated_rules:
                logger.warning("No valid rules extracted from document")
                return {'rules': []}
            
            logger.info(f"Successfully extracted {len(validated_rules)} valid rules")
            return {'rules': validated_rules}
            
        except Exception as e:
            logger.error(f"Error processing OpenAI response: {str(e)}")
            return {'rules': []}
            
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
    """Process a document and extract compliance rules with progress tracking."""
    try:
        # Update status to processing
        document.status = 'processing'
        db.session.commit()
        logger.info(f"Started processing document: {document.filename}")
        
        # Step 1: Extract text from PDF (25%)
        logger.info("Extracting text from PDF...")
        text = extract_pdf_text(file_path)
        document.content = text
        document.status = 'processing_25'
        db.session.commit()
        
        # Step 2: Process text and extract rules (50%)
        logger.info("Processing text and extracting rules...")
        processed_data = process_document_text(text)
        document.processed_content = text
        document.status = 'processing_50'
        db.session.commit()
        
        # Step 3: Validate extracted rules (75%)
        logger.info("Validating extracted rules...")
        valid_rules = [rule for rule in processed_data['rules'] if validate_rule(rule)]
        logger.info(f"Found {len(valid_rules)} valid rules out of {len(processed_data['rules'])} total rules")
        document.status = 'processing_75'
        db.session.commit()
        
        # Step 4: Create compliance rules (100%)
        logger.info("Creating compliance rules...")
        create_compliance_rules(document, valid_rules)
        document.status = 'processed'
        
        db.session.commit()
        logger.info(f"Successfully processed document: {document.filename}")
        
    except Exception as e:
        document.status = 'error'
        db.session.commit()
        logger.error(f"Error processing document {document.filename}: {str(e)}")
        raise

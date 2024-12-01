import os
import json
import logging
from typing import Dict, List, Optional
from werkzeug.utils import secure_filename
from pdfminer.high_level import extract_text
from openai import OpenAI
from database import db
from models import ComplianceDocument, ComplianceRule, CompliancePolicy

logger = logging.getLogger(__name__)

def validate_rule(rule_data: Dict) -> bool:
    """Validate extracted rule data structure."""
    try:
        required_fields = ['type', 'description', 'priority']
        if not all(field in rule_data for field in required_fields):
            return False
            
        if not isinstance(rule_data['priority'], (int, float)) or not (1 <= rule_data['priority'] <= 5):
            return False
            
        if not isinstance(rule_data['description'], str) or len(rule_data['description']) < 10:
            return False
            
        return True
        
    except Exception as e:
        logger.error(f"Error validating rule: {str(e)}")
        return False

def extract_pdf_text(file_path: str) -> str:
    """Extract text content from a PDF file."""
    try:
        text = extract_text(file_path)
        if not text:
            raise ValueError("No text content extracted from PDF")
        return text
    except Exception as e:
        logger.error(f"Error extracting text from PDF: {str(e)}")
        raise

def process_document_text(text: str, max_retries: int = 3) -> Dict[str, List[Dict]]:
    """Process document text using OpenAI to extract structured rules and requirements."""
    try:
        client = OpenAI()
        retry_count = 0
        last_error = None
        
        while retry_count < max_retries:
            try:
                system_prompt = """You are an expert compliance analyst specializing in security and access control. 
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

                response = client.chat.completions.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": text}
                    ],
                    temperature=0.7
                )

                content = response.choices[0].message.content
                if not content:
                    raise ValueError("Empty response from OpenAI")

                # Parse and validate the response
                data = json.loads(content)
                if not isinstance(data, dict) or 'rules' not in data:
                    raise ValueError("Invalid response format")

                rules = data['rules']
                if not isinstance(rules, list):
                    raise ValueError("Rules must be an array")

                validated_rules = [rule for rule in rules if validate_rule(rule)]
                logger.info(f"Successfully extracted {len(validated_rules)} valid rules")
                return {'rules': validated_rules}

            except json.JSONDecodeError as e:
                logger.error(f"JSON parsing error (attempt {retry_count + 1}): {str(e)}")
                last_error = e
                retry_count += 1
                if retry_count < max_retries:
                    logger.info(f"Retrying OpenAI request (attempt {retry_count + 1})")
                    continue
            except Exception as e:
                logger.error(f"Error processing OpenAI response (attempt {retry_count + 1}): {str(e)}")
                last_error = e
                retry_count += 1
                if retry_count < max_retries:
                    logger.info(f"Retrying OpenAI request (attempt {retry_count + 1})")
                    continue
            break

        if last_error:
            logger.error(f"All retries failed. Last error: {str(last_error)}")
            return {'rules': []}

    except Exception as e:
        logger.error(f"Error in process_document_text: {str(e)}")
        return {'rules': []}

def create_compliance_rules(document: ComplianceDocument, rules: List[Dict]) -> None:
    """Create ComplianceRule records from extracted rules."""
    try:
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
            db.session.add(rule)
            
        db.session.commit()
        logger.info(f"Successfully created {len(rules)} compliance rules for document {document.id}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating compliance rules: {str(e)}")
        raise

def create_policy_from_rules(rules: List[Dict]) -> Optional[Dict]:
    """Convert extracted rules into a compliance policy."""
    try:
        if not rules:
            return None
            
        # Group rules by type and priority
        high_priority_rules = [r for r in rules if r['priority'] >= 4]
        other_rules = [r for r in rules if r['priority'] < 4]
        
        # Determine policy category based on rule content
        categories = set()
        for rule in rules:
            if 'gdpr' in rule['description'].lower():
                categories.add('GDPR')
            if 'sox' in rule['description'].lower():
                categories.add('SOX')
            if 'hipaa' in rule['description'].lower():
                categories.add('HIPAA')
        
        category = next(iter(categories)) if categories else 'General'
        
        # Create policy name and description
        name = f"Auto-generated Policy - {category}"
        description = "Automatically generated from document analysis\n\n"
        
        # Add high priority rules first
        if high_priority_rules:
            description += "Critical Requirements:\n"
            for rule in high_priority_rules:
                description += f"- {rule['description']}\n"
        
        # Add other rules
        if other_rules:
            description += "\nAdditional Requirements:\n"
            for rule in other_rules:
                description += f"- {rule['description']}\n"
        
        # Create requirements section
        requirements = "Implementation Requirements:\n\n"
        for rule in rules:
            if 'actions' in rule and 'required_steps' in rule['actions']:
                requirements += f"Priority {rule['priority']} - {rule['type']}:\n"
                for step in rule['actions']['required_steps']:
                    requirements += f"- {step}\n"
        
        return {
            'name': name,
            'category': category,
            'description': description,
            'requirements': requirements
        }
        
    except Exception as e:
        logger.error(f"Error creating policy from rules: {str(e)}")
        return None

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
        
        # Step 4: Create compliance rules and policy (100%)
        logger.info("Creating compliance rules and policy...")
        create_compliance_rules(document, valid_rules)
        
        # Generate and create policy from rules
        policy_data = create_policy_from_rules(valid_rules)
        if policy_data:
            try:
                policy = CompliancePolicy(
                    name=policy_data['name'],
                    category=policy_data['category'],
                    description=policy_data['description'],
                    requirements=policy_data['requirements'],
                    status='active'
                )
                db.session.add(policy)
                logger.info(f"Created new compliance policy: {policy_data['name']}")
            except Exception as e:
                logger.error(f"Error creating policy: {str(e)}")
        
        document.status = 'processed'
        db.session.commit()
        logger.info(f"Successfully processed document: {document.filename}")
        
    except Exception as e:
        document.status = 'error'
        db.session.commit()
        logger.error(f"Error processing document {document.filename}: {str(e)}")
        raise
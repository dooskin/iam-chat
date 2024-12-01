import os
import json
import logging
from typing import Dict, List, Optional
from datetime import datetime
import time
from sqlalchemy.exc import SQLAlchemyError
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

def create_policy_from_rules(rules: List[Dict], document_id: int) -> Optional[Dict]:
    """Convert extracted rules into a compliance policy with unique naming."""
    try:
        if not rules:
            return None
            
        # Group rules by type and priority
        high_priority_rules = [r for r in rules if r['priority'] >= 4]
        other_rules = [r for r in rules if r['priority'] < 4]
        
        # Enhanced category detection with keyword mapping
        category_keywords = {
            'GDPR': ['gdpr', 'data protection', 'privacy', 'eu regulation'],
            'SOX': ['sox', 'sarbanes', 'financial control', 'audit'],
            'HIPAA': ['hipaa', 'health', 'medical', 'patient'],
            'PCI': ['pci', 'payment', 'card data', 'credit card'],
            'ISO27001': ['iso 27001', 'information security', 'isms'],
        }
        
        # Determine categories based on enhanced keyword matching
        categories = set()
        combined_text = ' '.join(rule['description'].lower() for rule in rules)
        
        for category, keywords in category_keywords.items():
            if any(keyword in combined_text for keyword in keywords):
                categories.add(category)
        
        primary_category = next(iter(categories)) if categories else 'General'
        
        # Generate unique policy name with timestamp and document ID
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        name = f"Policy_{primary_category}_{document_id}_{timestamp}"
        
        description = f"Auto-generated compliance policy for document {document_id}\n"
        description += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # Add detected categories
        if categories:
            description += "Compliance Categories: " + ", ".join(categories) + "\n\n"
        
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
        
        # Enhanced requirements section with better structure
        requirements = "Implementation Requirements:\n\n"
        priority_groups = {}
        
        for rule in rules:
            if 'actions' in rule and 'required_steps' in rule['actions']:
                priority = rule['priority']
                if priority not in priority_groups:
                    priority_groups[priority] = []
                priority_groups[priority].extend(rule['actions']['required_steps'])
        
        # Sort by priority (highest first) and deduplicate steps
        for priority in sorted(priority_groups.keys(), reverse=True):
            requirements += f"Priority {priority} Requirements:\n"
            unique_steps = list(dict.fromkeys(priority_groups[priority]))
            for step in unique_steps:
                requirements += f"- {step}\n"
            requirements += "\n"
        
        return {
            'name': name,
            'category': primary_category,
            'description': description,
            'requirements': requirements,
            'additional_categories': list(categories - {primary_category})
        }
        
    except Exception as e:
        logger.error(f"Error creating policy from rules: {str(e)}")
        return None

def process_document(document_id: int, file_path: str, max_retries: int = 3) -> None:
    """Process a document and extract compliance rules with enhanced error handling and retries."""
    session = db.session()
    
    def get_document():
        """Helper function to get document within the current session context."""
        return session.query(ComplianceDocument).get(document_id)
    
    def update_status(document: ComplianceDocument, new_status: str, commit: bool = True) -> None:
        """Helper function to update document status with proper error handling."""
        try:
            document.status = new_status
            if commit:
                session.commit()
                session.refresh(document)
            logger.info(f"Document {document.filename} status updated to: {new_status}")
        except Exception as e:
            session.rollback()
            logger.error(f"Error updating document status: {str(e)}")
            raise
    
    try:
        document = get_document()
        if not document:
            raise ValueError(f"Document with ID {document_id} not found")

        update_status(document, 'processing')
        logger.info(f"Started processing document: {document.filename}")
        
        # Step 1: Extract text from PDF (25%)
        logger.info("Extracting text from PDF...")
        text = extract_pdf_text(file_path)
        document.content = text
        update_status(document, 'processing_25')
        
        # Step 2: Process text and extract rules (50%)
        logger.info("Processing text and extracting rules...")
        processed_data = process_document_text(text)
        document.processed_content = text
        update_status(document, 'processing_50')
        
        # Step 3: Validate extracted rules (75%)
        logger.info("Validating extracted rules...")
        valid_rules = [rule for rule in processed_data['rules'] if validate_rule(rule)]
        logger.info(f"Found {len(valid_rules)} valid rules out of {len(processed_data['rules'])} total rules")
        update_status(document, 'processing_75')
        
        # Step 4: Create compliance rules and policy (100%)
        logger.info("Creating compliance rules and policy...")
        
        # Use transaction for rules creation
        try:
            session.refresh(document)  # Ensure document is fresh in session
            create_compliance_rules(document, valid_rules)
            session.flush()  # Ensure rules are created before policy
            session.refresh(document)  # Refresh after rules creation
        except Exception as e:
            session.rollback()
            logger.error(f"Error creating compliance rules: {str(e)}")
            raise
        
        # Policy creation with retry logic
        retry_count = 0
        policy_created = False
        last_error = None
        
        while retry_count < max_retries and not policy_created:
            try:
                # Generate policy data with unique name
                policy_data = create_policy_from_rules(valid_rules, document.id)
                
                if policy_data:
                    # Start a nested transaction for policy creation
                    with session.begin_nested():
                        policy = CompliancePolicy(
                            name=policy_data['name'],
                            category=policy_data['category'],
                            description=policy_data['description'],
                            requirements=policy_data['requirements'],
                            status='active'
                        )
                        session.add(policy)
                        session.flush()
                        policy_created = True
                        logger.info(f"Created new compliance policy: {policy_data['name']}")
                        
                        # Create additional category policies if needed
                        for additional_category in policy_data.get('additional_categories', []):
                            category_policy = CompliancePolicy(
                                name=f"{policy_data['name']}_{additional_category}",
                                category=additional_category,
                                description=policy_data['description'],
                                requirements=policy_data['requirements'],
                                status='active'
                            )
                            session.add(category_policy)
                        
                break  # Exit retry loop if successful
                
            except Exception as e:
                session.rollback()
                last_error = e
                retry_count += 1
                logger.warning(f"Policy creation attempt {retry_count} failed: {str(e)}")
                if retry_count < max_retries:
                    time.sleep(1)  # Add delay between retries
        
        if not policy_created:
            logger.error(f"Failed to create policy after {max_retries} attempts. Last error: {str(last_error)}")
            update_status(document, 'partial_success', commit=False)
        else:
            update_status(document, 'processed', commit=False)
        
        # Final commit for the entire transaction
        session.commit()
        session.refresh(document)  # Final refresh after all operations
        logger.info(f"Successfully processed document: {document.filename}")
        
    except Exception as e:
        session.rollback()
        # Get fresh document instance for error status update
        error_doc = get_document()
        if error_doc:
            update_status(error_doc, 'error')
        logger.error(f"Error processing document {document_id}: {str(e)}")
        raise
        
    finally:
        session.close()
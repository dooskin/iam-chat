import os
import magic
import logging
from typing import Dict, List, Optional
import spacy
from pdfminer.high_level import extract_text
import pytesseract
from PIL import Image
from models import ComplianceDocument, ComplianceRule
from database import db

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
    """Process document text using NLP to extract rules and requirements."""
    if nlp is None:
        logger.warning("NLP model not available, using basic text processing")
        return {'rules': [{'type': 'requirement', 
                          'description': text,
                          'conditions': {'subject': 'document', 'condition': None},
                          'actions': {'action': 'review'},
                          'priority': 1}]}
    
    doc = nlp(text)
    rules = []
    
    # Keywords that might indicate rules or requirements
    rule_indicators = ['must', 'shall', 'required', 'should', 'need to', 'mandatory']
    
    for sent in doc.sents:
        # Check if sentence contains rule indicators
        if any(indicator in sent.text.lower() for indicator in rule_indicators):
            # Analyze sentence structure
            subject = None
            action = None
            condition = None
            
            for token in sent:
                if token.dep_ == 'nsubj':
                    subject = token.text
                elif token.dep_ == 'ROOT' and token.pos_ == 'VERB':
                    action = token.text
                elif token.dep_ == 'advcl':
                    condition = token.text
            
            if subject and action:
                rule = {
                    'type': 'requirement',
                    'description': sent.text.strip(),
                    'conditions': {
                        'subject': subject,
                        'condition': condition
                    },
                    'actions': {
                        'action': action
                    },
                    'priority': 1
                }
                rules.append(rule)
    
    return {'rules': rules}

def create_compliance_rules(document: ComplianceDocument, rules: List[Dict]) -> None:
    """Create ComplianceRule objects from extracted rules."""
    try:
        for rule_data in rules:
            rule = ComplianceRule(
                document_id=document.id,
                rule_type=rule_data['type'],
                description=rule_data['description'],
                conditions=rule_data['conditions'],
                actions=rule_data['actions'],
                priority=rule_data['priority']
            )
            db.session.add(rule)
        db.session.commit()
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

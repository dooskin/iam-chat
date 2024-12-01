import os
import json
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.exc import SQLAlchemyError
from database import db
from models import User, ComplianceDocument, ComplianceRule, CompliancePolicy, ComplianceRecord
from chatbot import process_chat_message
from policy_engine import evaluate_access_request
from document_processor import process_document

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('chat.html')

@app.route('/compliance')
@login_required
def compliance():
    """ComplianceHub main view."""
    try:
        documents = ComplianceDocument.query.order_by(ComplianceDocument.upload_date.desc()).all()
        policies = CompliancePolicy.query.order_by(CompliancePolicy.updated_at.desc()).all()
        records = ComplianceRecord.query.order_by(ComplianceRecord.updated_at.desc()).limit(10).all()
        
        # Calculate statistics
        stats = {
            'total_documents': ComplianceDocument.query.count(),
            'active_policies': CompliancePolicy.query.filter_by(status='active').count(),
            'pending_reviews': ComplianceRecord.query.filter_by(status='pending_review').count(),
            'compliance_rate': calculate_compliance_rate()
        }
        
        return render_template('compliance.html', 
                             documents=documents,
                             policies=policies,
                             records=records,
                             stats=stats)
    except Exception as e:
        logger.error(f"Error loading ComplianceHub: {str(e)}")
        flash('Error loading ComplianceHub', 'danger')
        return redirect(url_for('index'))

def calculate_compliance_rate():
    """Calculate overall compliance rate."""
    try:
        total = ComplianceRecord.query.count()
        if total == 0:
            return 100
        compliant = ComplianceRecord.query.filter_by(status='compliant').count()
        return round((compliant / total) * 100)
    except Exception as e:
        logger.error(f"Error calculating compliance rate: {str(e)}")
        return 0

@app.route('/compliance/upload', methods=['POST'])
@login_required
def upload_compliance_document():
    """Handle compliance document upload."""
    if 'document' not in request.files:
        flash('No document provided', 'danger')
        return redirect(url_for('compliance'))
        
    file = request.files['document']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('compliance'))
        
    try:
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            document = ComplianceDocument(
                filename=filename,
                uploaded_by=current_user.id,
                status='pending'
            )
            db.session.add(document)
            db.session.commit()
            
            # Process document asynchronously
            process_document(document, filepath)
            
            flash('Document uploaded successfully', 'success')
            return redirect(url_for('compliance'))
            
    except Exception as e:
        logger.error(f"Error uploading document: {str(e)}")
        flash('Error uploading document', 'danger')
        return redirect(url_for('compliance'))

@app.route('/compliance/policy/<int:policy_id>')
@login_required
def view_policy(policy_id):
    """View details of a specific compliance policy."""
    try:
        policy = CompliancePolicy.query.get_or_404(policy_id)
        records = ComplianceRecord.query.filter_by(policy_id=policy_id).all()
        
        # Get associated rules based on policy category and description
        rules = ComplianceRule.query.join(ComplianceDocument).filter(
            ComplianceDocument.status == 'processed'
        ).all()
        
        # Filter rules based on policy content
        policy_rules = []
        for rule in rules:
            if (policy.category.lower() in rule.description.lower() or
                any(phrase in rule.description.lower() 
                    for phrase in policy.description.lower().split())):
                policy_rules.append(rule)
        
        return render_template('policy_detail.html', 
                             policy=policy, 
                             records=records, 
                             rules=policy_rules)
    except Exception as e:
        logger.error(f"Error viewing policy {policy_id}: {str(e)}")
        flash('Error loading policy details', 'danger')
        return redirect(url_for('compliance'))

@app.route('/compliance/document/status/<filename>')
@login_required
def get_document_status(filename):
    """Get the processing status of a compliance document."""
    try:
        document = ComplianceDocument.query.filter_by(filename=filename).first()
        if not document:
            return jsonify({'status': 'error', 'message': 'Document not found'}), 404
        return jsonify({'status': document.status})
    except Exception as e:
        logger.error(f"Error fetching document status: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/compliance/document/<int:doc_id>/rules')
@login_required
def get_document_rules(doc_id):
    """Fetch rules for a specific compliance document."""
    try:
        document = ComplianceDocument.query.get_or_404(doc_id)
        rules = document.rules.all()
        
        rules_data = [{
            'type': rule.rule_type,
            'description': rule.description,
            'conditions': rule.conditions,
            'actions': rule.actions,
            'priority': rule.priority
        } for rule in rules]
        
        return jsonify({'rules': rules_data})
    except Exception as e:
        logger.error(f"Error fetching document rules: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/settings/update', methods=['POST'])
@login_required
def update_settings():
    try:
        email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')

        if email and email != current_user.email:
            current_user.email = email
            flash('Email updated successfully', 'success')

        if current_password and new_password:
            if check_password_hash(current_user.password_hash, current_password):
                current_user.password_hash = generate_password_hash(new_password)
                flash('Password updated successfully', 'success')
            else:
                flash('Current password is incorrect', 'danger')

        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Error updating settings', 'danger')
        logger.error(f'Error updating settings: {str(e)}')

    return redirect(url_for('settings'))

@app.route('/api/chat', methods=['POST'])
@login_required
def chat():
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 400
        
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({'error': 'No message provided'}), 400
        
    message = data['message']

    try:
        # Process message through chatbot
        response = process_chat_message(message, current_user)
        
        # Evaluate access request if present
        if 'access_request' in response:
            access_decision = evaluate_access_request(
                current_user.id,
                response['access_request']['resource'],
                response['access_request']['action']
            )
            response['access_decision'] = access_decision
        
        return jsonify(response)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

with app.app_context():
    try:
        # Verify database connection
        db.engine.connect()
        logger.info("Database connection successful")
        
        db.create_all()
        logger.info("Database tables created successfully")
        
        # Create admin user if it doesn't exist
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin123'),
                role='admin'
            )
            try:
                db.session.add(admin_user)
                db.session.commit()
                logger.info("Admin user created successfully")
            except SQLAlchemyError as e:
                db.session.rollback()
                logger.error(f"Error creating admin user: {str(e)}")
        else:
            logger.info("Admin user already exists")
            
    except SQLAlchemyError as e:
        logger.error(f"Database initialization error: {str(e)}")
        raise

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

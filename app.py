import os
import logging
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy.exc import SQLAlchemyError
from chatbot import process_chat_message
from database import db
from models import User, CompliancePolicy, ComplianceRecord, ComplianceDocument
from werkzeug.utils import secure_filename
from document_processor import process_document
from policy_engine import evaluate_access_request
from typing import Union, Optional

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Initialize Flask app config
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)

# Configure login manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

@login_manager.unauthorized_handler
def unauthorized():
    """Handle unauthorized access attempts."""
    logger.warning(f'Unauthorized access attempt to {request.url}')
    flash('You must be logged in to view this page.', 'warning')
    return redirect(url_for('login', next=request.url))

@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    """Load user by ID for Flask-Login."""
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        logger.error(f'Error loading user {user_id}: {str(e)}')
        return None

@app.route('/')
@login_required
def index():
    """Render the main chat interface."""
    logger.info(f'User {current_user.username} accessed the chat interface')
    return render_template('chat.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if current_user.is_authenticated:
        logger.debug('Already authenticated user accessing login page')
        return redirect(url_for('index'))

    next_page = request.args.get('next')
    if next_page and not next_page.startswith('/'):
        logger.warning(f'Invalid next parameter detected: {next_page}')
        next_page = None

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            logger.warning('Login attempt with missing credentials')
            return render_template('login.html', error='Username and password are required')
        
        try:
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password_hash, password):
                login_user(user, remember=True)
                session['user_role'] = user.role
                session.permanent = True
                logger.info(f'Successful login for user: {username}')
                target = next_page if next_page else url_for('index')
                logger.debug(f'Redirecting user {username} to: {target}')
                return redirect(target)
            
            logger.warning(f'Failed login attempt for username: {username}')
            return render_template('login.html', error='Invalid username or password')
            
        except SQLAlchemyError as e:
            logger.error(f'Database error during login: {str(e)}')
            db.session.rollback()
            return render_template('login.html', error='An error occurred. Please try again.')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    logout_user()
    return redirect(url_for('login'))

def admin_required(f):
    """Decorator to require admin role for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/users')
@login_required
@admin_required
def users():
    """Display all users (admin only)."""
    users_list = User.query.all()
    return render_template('users.html', users=users_list)

@app.route('/users/add', methods=['POST'])
@login_required
@admin_required
def add_user():
    """Add a new user (admin only)."""
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role')

    if not all([username, email, password, role]):
        flash('All fields are required', 'danger')
        return redirect(url_for('users'))

    if role not in ['user', 'admin']:
        flash('Invalid role specified', 'danger')
        return redirect(url_for('users'))

    try:
        existing_user = User.query.filter(
            db.or_(User.username == username, User.email == email)
        ).first()
        
        if existing_user:
            flash('Username or email already exists', 'danger')
            return redirect(url_for('users'))

        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role=role
        )
        
        db.session.add(new_user)
        db.session.commit()
        flash('User added successfully', 'success')
        
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Error adding user', 'danger')
        logger.error(f'Error adding user: {str(e)}')
        
    return redirect(url_for('users'))

@app.route('/users/<int:user_id>/role', methods=['POST'])
@login_required
@admin_required
def update_user_role(user_id: int):
    """Update a user's role (admin only)."""
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    
    if new_role not in ['user', 'admin']:
        flash('Invalid role specified', 'danger')
        return redirect(url_for('users'))
        
    try:
        user.role = new_role
        db.session.commit()
        flash('User role updated successfully', 'success')
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Error updating user role', 'danger')
        logger.error(f'Error updating user role: {str(e)}')
        
    return redirect(url_for('users'))

@app.route('/integrations')
@login_required
def integrations():
    """Display integrations page."""
    return render_template('integrations.html')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """Display user settings page."""
    return render_template('settings.html')

@app.route('/settings/update', methods=['POST'])
@login_required
def update_settings():
    """
    Update user settings including email, password, and notification preferences.
    
    This function handles:
    1. Email updates with duplicate checking
    2. Password changes with validation
    3. Notification preference updates
    
    Returns:
        Response: Redirect to settings page with appropriate flash messages
    """
    try:
        # Update email
        email = request.form.get('email')
        if email and email != current_user.email:
            # Check if email is already in use
            if User.query.filter_by(email=email).first():
                flash('Email already in use', 'danger')
                return redirect(url_for('settings'))
            current_user.email = email
            flash('Email updated successfully', 'success')

        # Update password
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if current_password and new_password and confirm_password:
            if new_password != confirm_password:
                flash('New passwords do not match', 'danger')
                return redirect(url_for('settings'))
                
            if not check_password_hash(current_user.password_hash, current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('settings'))
                
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long', 'danger')
                return redirect(url_for('settings'))
                
            current_user.password_hash = generate_password_hash(new_password)
            flash('Password updated successfully', 'success')

        # Update notification preferences
        notification_prefs = {}
        for pref in ['email_notifications', 'security_alerts', 'compliance_updates']:
            notification_prefs[pref] = request.form.get(pref) == 'on'
        
        current_user.notification_preferences = notification_prefs
        flash('Notification preferences updated successfully', 'success')

        db.session.commit()
        
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Error updating settings', 'danger')
        logger.error(f'Error updating settings: {str(e)}')

    return redirect(url_for('settings'))

@app.route('/compliance')
@login_required
def compliance():
    """Display compliance dashboard with statistics and documents."""
    stats = {
        'total_documents': ComplianceDocument.query.count(),
        'active_policies': CompliancePolicy.query.filter_by(status='active').count(),
        'pending_reviews': ComplianceRecord.query.filter_by(status='pending_review').count()
    }
    
    # Calculate compliance rate
    total_records = ComplianceRecord.query.count()
    compliant_records = ComplianceRecord.query.filter_by(status='compliant').count()
    stats['compliance_rate'] = round((compliant_records / total_records * 100) if total_records > 0 else 0)
    
    # Get documents and their processing status
    documents = ComplianceDocument.query.order_by(ComplianceDocument.upload_date.desc()).all()
    
    # Get policies and recent records
    policies = CompliancePolicy.query.order_by(CompliancePolicy.updated_at.desc()).all()
    records = ComplianceRecord.query.order_by(ComplianceRecord.updated_at.desc()).limit(10).all()
    
    return render_template('compliance.html',
                         stats=stats,
                         policies=policies,
                         documents=documents,
                         records=records)

@app.route('/compliance/policy', methods=['POST'])
@login_required
def add_compliance_policy():
    """Add a new compliance policy (admin only)."""
    if current_user.role != 'admin':
        flash('Permission denied', 'danger')
        return redirect(url_for('compliance'))
        
    try:
        policy = CompliancePolicy(
            name=request.form['name'],
            category=request.form['category'],
            description=request.form['description'],
            requirements=request.form['requirements']
        )
        db.session.add(policy)
        db.session.commit()
        flash('Compliance policy added successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding policy: {str(e)}', 'danger')
        
    return redirect(url_for('compliance'))

@app.route('/compliance/document/upload', methods=['POST'])
@login_required
def upload_compliance_document():
    """
    Handle compliance document upload and processing.
    
    This function:
    1. Validates user permissions
    2. Processes uploaded PDF file
    3. Creates document record
    4. Initiates document processing
    """
    if current_user.role != 'admin':
        logger.warning(f"Non-admin user {current_user.username} attempted to upload document")
        flash('Permission denied', 'danger')
        return redirect(url_for('compliance'))
    
    if 'document' not in request.files:
        logger.warning("Document upload attempted without file")
        flash('No document provided', 'danger')
        return redirect(url_for('compliance'))
    
    file = request.files['document']
    if not file or file.filename == '':
        logger.warning("Empty file uploaded")
        flash('No selected file', 'danger')
        return redirect(url_for('compliance'))
    
    if not file.filename.lower().endswith('.pdf'):
        logger.warning(f"Invalid file type attempted: {file.filename}")
        flash('Only PDF files are allowed', 'danger')
        return redirect(url_for('compliance'))
    
    try:
        filename = secure_filename(file.filename)
        upload_dir = os.path.join(app.instance_path, 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, filename)
        file.save(file_path)
        
        document = ComplianceDocument(
            filename=filename,
            uploaded_by=current_user.id,
            status='pending'
        )
        db.session.add(document)
        db.session.flush()  # Ensure document has an ID before processing
        
        # Store document_id before processing
        document_id = document.id
        db.session.commit()
        
        try:
            # Process document using stored ID
            process_document(document_id, file_path)
            flash('Document processed successfully', 'success')
        except Exception as e:
            logger.error(f"Error processing document {filename}: {str(e)}")
            # Get fresh document instance
            error_doc = ComplianceDocument.query.get(document_id)
            if error_doc:
                error_doc.status = 'error'
                db.session.commit()
            flash('Error processing document: Please check the file format and try again', 'danger')
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in document upload: {str(e)}")
        flash('Error uploading document: Please try again', 'danger')
        
    return redirect(url_for('compliance'))

@app.route('/compliance/policy/<int:policy_id>')
@login_required
def view_policy(policy_id: int):
    """View details of a specific compliance policy."""
    policy = CompliancePolicy.query.get_or_404(policy_id)
    records = ComplianceRecord.query.filter_by(policy_id=policy_id).all()
    return render_template('policy_detail.html', policy=policy, records=records)

@app.route('/compliance/document/<int:doc_id>/delete', methods=['POST'])
@login_required
def delete_compliance_document(doc_id: int):
    """Delete a compliance document and its associated rules."""
    try:
        document = ComplianceDocument.query.get_or_404(doc_id)
        
        # Only allow admins to delete documents
        if current_user.role != 'admin':
            flash('Permission denied', 'danger')
            return redirect(url_for('compliance'))
            
        # Delete associated rules first
        document.rules.delete()
        
        # Delete the document
        db.session.delete(document)
        db.session.commit()
        
        flash('Document deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f'Error deleting document: {str(e)}')
        flash('Error deleting document', 'danger')
        
    return redirect(url_for('compliance'))

@app.route('/compliance/document/status/<filename>')
@login_required
def get_document_status(filename: str):
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
def get_document_rules(doc_id: int):
    """Fetch rules for a specific compliance document."""
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

@app.route('/api/chat', methods=['POST'])
@login_required
@app.route('/connectors')
@login_required
def connectors():
    """Display the connectors page with GCP and Neo4j connection status."""
    gcp_connected = False
    gcp_project_id = None
    gcp_email = None
    
    try:
        if 'gcp_token' in session:
            credentials = gcp_connector.load_credentials()
            if credentials:
                project_info = gcp_connector.get_project_info()
                gcp_connected = True
                gcp_project_id = project_info['project_id']
                # Get user email from session
                gcp_email = session.get('gcp_email')
    except Exception as e:
        logger.error(f"Error loading GCP credentials: {str(e)}")
        
    # Get Neo4j connection info
    neo4j_connected = neo4j_connector.is_connected()
    neo4j_info = neo4j_connector.get_connection_info()
    
    return render_template('connectors.html',
                         gcp_connected=gcp_connected,
                         gcp_project_id=gcp_project_id,
                         gcp_email=gcp_email,
                         neo4j_connected=neo4j_connected,
                         neo4j_uri=neo4j_info['uri'],
                         neo4j_user=neo4j_info['user'])

@app.route('/authorize_gcp')
@login_required
def authorize_gcp():
    """Start GCP OAuth flow."""
    try:
        redirect_uri = url_for('oauth2callback', _external=True)
        auth_url = gcp_connector.create_authorization_url(redirect_uri)
        return redirect(auth_url)
    except Exception as e:
        flash(f"Error starting authorization: {str(e)}", 'danger')
        return redirect(url_for('connectors'))

@app.route('/oauth2callback')
@login_required
def oauth2callback():
    """Handle GCP OAuth callback."""
    try:
        if 'error' in request.args:
            flash(f"Authorization failed: {request.args['error']}", 'danger')
            return redirect(url_for('connectors'))
            
        code = request.args.get('code')
        if not code:
            flash('No authorization code received', 'danger')
            return redirect(url_for('connectors'))
            
        redirect_uri = url_for('oauth2callback', _external=True)
        credentials = gcp_connector.get_credentials_from_code(code, redirect_uri)
        gcp_connector.store_credentials(credentials)
        
        # Store user email in session
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        session['gcp_email'] = user_info.get('email')
        
        flash('Successfully connected to Google Cloud Platform', 'success')
        
    except Exception as e:
        flash(f"Error during authorization: {str(e)}", 'danger')
        
    return redirect(url_for('connectors'))

@app.route('/disconnect_gcp', methods=['POST'])
@login_required
def disconnect_gcp():
    """Disconnect GCP account."""
    session.pop('gcp_token', None)
    session.pop('gcp_email', None)
    flash('Disconnected from Google Cloud Platform', 'success')
    return redirect(url_for('connectors'))

@app.route('/update_neo4j_connection', methods=['POST'])
@login_required
def update_neo4j_connection():
    """Update Neo4j database connection."""
    uri = request.form.get('neo4j_uri')
    user = request.form.get('neo4j_user')
    password = request.form.get('neo4j_password')
    
    if not all([uri, user, password]):
        flash('All fields are required', 'danger')
        return redirect(url_for('connectors'))
        
    try:
        if neo4j_connector.connect(uri, user, password):
            neo4j_connector.store_connection_info(uri, user)
            flash('Successfully connected to Neo4j database', 'success')
        else:
            flash('Failed to connect to Neo4j database', 'danger')
    except Exception as e:
        flash(f'Error connecting to Neo4j: {str(e)}', 'danger')
        
    return redirect(url_for('connectors'))
def chat():
    """Handle chat API requests with access control evaluation."""
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
        admin_user = User.query.filter_by(username='admin69!').first()
        if not admin_user:
            logger.info("Creating admin user...")
            admin_user = User(
                username='admin69!',
                email='admin@example.com',
                password_hash=generate_password_hash('admin69!'),
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
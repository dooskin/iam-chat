import os
import time
import random
from urllib.parse import urlparse
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.cloud import asset_v1
import neo4j
from typing import Optional, Dict, Any, List, Union
import logging
from neo4j.exceptions import (
    ServiceUnavailable,
    AuthError,
    DatabaseError,
    TransientError,
    ClientError
)

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GCPConnector:
    """Handles Google Cloud Platform integration and data retrieval."""
    
    SCOPES = [
        'https://www.googleapis.com/auth/cloud-platform.read-only',
        'https://www.googleapis.com/auth/cloud-identity.groups.readonly',
        'https://www.googleapis.com/auth/admin.directory.group.readonly'
    ]

    def __init__(self):
        # Validate Google OAuth credentials
        self.client_id = os.environ.get('GOOGLE_CLIENT_ID')
        self.client_secret = os.environ.get('GOOGLE_CLIENT_SECRET')
        
        if not self.client_id or not self.client_secret:
            error_msg = "Missing required Google OAuth credentials"
            logger.error(error_msg)
            raise ValueError(error_msg)
            
        # Validate Neo4j credentials
        self.neo4j_uri = os.environ.get('NEO4J_URI')
        self.neo4j_user = os.environ.get('NEO4J_USER')
        self.neo4j_password = os.environ.get('NEO4J_PASSWORD')
        
        if not all([self.neo4j_uri, self.neo4j_user, self.neo4j_password]):
            error_msg = "Missing required Neo4j credentials"
            logger.error(error_msg)
            raise ValueError(error_msg)
            
        self._driver = None
        logger.info("GCPConnector initialized successfully")

    @property
    def neo4j_driver(self):
        """Lazy initialization of Neo4j driver with enhanced connection pooling and retry logic."""
        if self._driver is None:
            retry_count = 0
            max_retries = 5  # Increased max retries
            base_delay = 1  # Base delay in seconds
            max_delay = 32  # Maximum delay in seconds

            while retry_count < max_retries:
                try:
                    # Validate Neo4j configuration
                    if not all([self.neo4j_uri, self.neo4j_user, self.neo4j_password]):
                        raise ValueError("Missing required Neo4j credentials")

                    if not self.neo4j_uri.startswith(('bolt://', 'neo4j://', 'neo4j+s://')):
                        raise ValueError("Invalid Neo4j URI format")

                    # Configure connection pooling with optimized settings
                    self._driver = neo4j.GraphDatabase.driver(
                        self.neo4j_uri,
                        auth=(self.neo4j_user, self.neo4j_password),
                        max_connection_lifetime=3600,  # 1 hour
                        max_connection_pool_size=50,   # Adjust based on expected concurrent connections
                        connection_acquisition_timeout=60,  # 60 seconds
                        connection_timeout=30,  # 30 seconds connection timeout
                        max_retry_time=30,  # Maximum time to retry transactions
                        keep_alive=True     # Enable keep-alive
                    )
                    
                    # Test the connection with timeout
                    with self._driver.session(database="neo4j", fetch_size=1) as session:
                        # Use parameter to prevent injection
                        result = session.run("RETURN $test_value AS test", 
                                           test_value=1,
                                           timeout=10)  # 10 second timeout
                        result.single()
                        logger.info("Successfully established Neo4j connection with verified access")
                        
                        # Get Neo4j server version for logging
                        version_result = session.run("CALL dbms.components() YIELD name, versions RETURN name, versions")
                        version_info = version_result.single()
                        if version_info:
                            logger.info(f"Connected to Neo4j {version_info['name']} version {version_info['versions'][0]}")
                        
                    # Initialize schema with separate retry logic
                    try:
                        self._initialize_schema()
                    except Exception as schema_error:
                        logger.error(f"Schema initialization failed: {str(schema_error)}")
                        self._driver.close()
                        self._driver = None
                        raise
                        
                    break  # Exit loop if successful
                    
                except (neo4j.exceptions.ServiceUnavailable,
                       neo4j.exceptions.DatabaseError,
                       neo4j.exceptions.TransientError) as e:
                    retry_count += 1
                    if retry_count == max_retries:
                        error_msg = f"Failed to establish Neo4j connection after {max_retries} attempts: {str(e)}"
                        logger.error(error_msg)
                        raise ConnectionError(error_msg)
                    
                    # Calculate delay with exponential backoff and jitter
                    delay = min(base_delay * (2 ** (retry_count - 1)) + random.uniform(0, 1), max_delay)
                    logger.warning(f"Neo4j connection attempt {retry_count} failed ({str(e)}), retrying in {delay:.2f} seconds...")
                    time.sleep(delay)
                    
                except Exception as e:
                    error_msg = f"Unexpected error during Neo4j initialization: {str(e)}"
                    logger.error(error_msg)
                    if self._driver:
                        self._driver.close()
                        self._driver = None
                    raise ConnectionError(error_msg)
                    
        return self._driver

    def _initialize_schema(self):
        """Initialize Neo4j database schema with enhanced User node support and proper constraints."""
        max_retries = 3
        base_delay = 1  # Base delay in seconds
        retry_count = 0
        last_error = None

        while retry_count < max_retries:
            try:
                with self.neo4j_driver.session() as session:
                    # Verify database connectivity with timeout
                    session.run("RETURN 1", timeout=5)

                    # Define schema components
                    schema_components = [
                        # Node labels and their required properties
                        {
                            "label": "User",
                            "properties": {
                                "id": "INTEGER",
                                "credentials": "MAP",  # Store OAuth credentials as a map
                                "email": "STRING",
                                "created_at": "DATETIME"
                            },
                            "unique": ["id"]  # Properties that should have uniqueness constraints
                        },
                        {
                            "label": "IAMPolicy",
                            "properties": {
                                "name": "STRING",
                                "role": "STRING",
                                "created_at": "DATETIME"
                            },
                            "unique": ["name"]
                        },
                        {
                            "label": "Asset",
                            "properties": {
                                "name": "STRING",
                                "type": "STRING",
                                "created_at": "DATETIME"
                            },
                            "unique": ["name"]
                        }
                    ]

                    # Create or update schema for each component
                    for component in schema_components:
                        label = component["label"]
                        
                        # Create constraints for unique properties
                        for prop in component["unique"]:
                            constraint_name = f"{label.lower()}_{prop}_unique"
                            try:
                                # Drop existing constraint if it exists (to handle schema changes)
                                session.run(f"""
                                    DROP CONSTRAINT {constraint_name} IF EXISTS
                                """)
                                
                                # Create new constraint
                                session.run(f"""
                                    CREATE CONSTRAINT {constraint_name} IF NOT EXISTS
                                    FOR (n:{label})
                                    REQUIRE n.{prop} IS UNIQUE
                                """)
                                logger.info(f"Created/updated constraint: {constraint_name}")
                            except Exception as e:
                                error_msg = f"Error managing constraint {constraint_name}: {str(e)}"
                                logger.error(error_msg)
                                raise ValueError(error_msg)

                        # Create indexes for non-unique properties that need fast lookup
                        for prop, prop_type in component["properties"].items():
                            if prop not in component["unique"]:
                                index_name = f"{label.lower()}_{prop}_idx"
                                try:
                                    session.run(f"""
                                        CREATE INDEX {index_name} IF NOT EXISTS
                                        FOR (n:{label})
                                        ON (n.{prop})
                                    """)
                                    logger.info(f"Created/verified index: {index_name}")
                                except Exception as e:
                                    error_msg = f"Error creating index {index_name}: {str(e)}"
                                    logger.error(error_msg)
                                    raise ValueError(error_msg)

                    # Verify schema setup
                    constraints = session.run("SHOW CONSTRAINTS").data()
                    indexes = session.run("SHOW INDEXES").data()
                    
                    logger.info(f"Active constraints: {len(constraints)}")
                    logger.info(f"Active indexes: {len(indexes)}")
                    
                    # Schema initialization complete
                    logger.info("Neo4j schema initialization completed successfully")
                    return  # Success, exit the retry loop
                    
            except (neo4j.exceptions.ServiceUnavailable, 
                   neo4j.exceptions.DatabaseError,
                   neo4j.exceptions.TransientError) as e:
                retry_count += 1
                last_error = str(e)
                
                if retry_count == max_retries:
                    error_msg = f"Failed to initialize Neo4j schema after {max_retries} attempts. Last error: {last_error}"
                    logger.error(error_msg)
                    raise ConnectionError(error_msg)
                
                # Calculate delay with jitter
                max_delay = base_delay * (2 ** (retry_count - 1))
                delay = max_delay + random.uniform(0, 1)
                logger.warning(f"Schema initialization attempt {retry_count} failed, retrying in {delay:.2f} seconds...")
                time.sleep(delay)
                
            except Exception as e:
                error_msg = f"Unexpected error during schema initialization: {str(e)}"
                logger.error(error_msg)
                raise ValueError(error_msg)

    def create_oauth_flow(self, request_host: str = None) -> Flow:
        """Create OAuth2.0 flow for Google authentication with enhanced validation.
        
        Args:
            request_host: The host of the current request, used for dynamic callback URL.
                        Should include protocol (http/https).
        
        Returns:
            Flow: Configured OAuth2.0 flow object
            
        Raises:
            ValueError: If client credentials are invalid or misconfigured
            ConnectionError: If unable to validate credentials
        """
        try:
            # Enhanced credential validation with detailed checks
            if not self.client_id or not isinstance(self.client_id, str):
                error_msg = "Invalid Google client ID: must be a non-empty string"
                logger.error(error_msg)
                raise ValueError(error_msg)
                
            if not self.client_id.endswith('.apps.googleusercontent.com'):
                error_msg = "Invalid Google client ID format: must be a valid OAuth 2.0 client ID ending with .apps.googleusercontent.com"
                logger.error(error_msg)
                raise ValueError(error_msg)
                
            if not self.client_secret or not isinstance(self.client_secret, str):
                error_msg = "Invalid Google client secret: must be a non-empty string"
                logger.error(error_msg)
                raise ValueError(error_msg)
                
            if len(self.client_secret) < 24:  # Google client secrets are typically longer
                error_msg = "Invalid Google client secret: insufficient length for OAuth 2.0 client secret"
                logger.error(error_msg)
                raise ValueError(error_msg)

            # Build and validate dynamic callback URL with enhanced security
            if not request_host:
                error_msg = "Request host is required for dynamic callback URL configuration"
                logger.error(error_msg)
                raise ValueError(error_msg)
                
            if not isinstance(request_host, str):
                error_msg = "Request host must be a string value"
                logger.error(error_msg)
                raise ValueError(error_msg)
                
            if not request_host.startswith(('http://', 'https://')):
                error_msg = "Invalid request host format - must include valid protocol (http:// or https://)"
                logger.error(error_msg)
                raise ValueError(error_msg)

            # Normalize and validate callback URL with strict formatting
            callback_path = '/google/callback'  # Updated to match the route in app.py
            callback_url = request_host.rstrip('/') + callback_path
            
            # Strict URL validation
            try:
                parsed_url = urlparse(callback_url)
                if not all([
                    parsed_url.scheme in ('http', 'https'),
                    parsed_url.netloc,
                    parsed_url.path == callback_path
                ]):
                    raise ValueError("Invalid callback URL structure")
            except Exception as e:
                error_msg = f"Invalid callback URL format: {str(e)}"
                logger.error(error_msg)
                raise ValueError(error_msg)
                
            logger.info(f"Using validated callback URL: {callback_url}")

            # Enhanced scope validation with format checking
            if not isinstance(self.SCOPES, list):
                error_msg = "OAuth scopes configuration must be a list"
                logger.error(error_msg)
                raise ValueError(error_msg)
                
            if not all(isinstance(s, str) and s.startswith('https://www.googleapis.com/auth/') for s in self.SCOPES):
                error_msg = "Invalid OAuth scopes: all scopes must be valid Google API URLs"
                logger.error(error_msg)
                raise ValueError(error_msg)

            # Create OAuth config with comprehensive structure
            oauth_config = {
                "installed": {  # Changed from "web" to "installed" for better compatibility
                    "client_id": self.client_id,
                    "project_id": os.environ.get('GOOGLE_PROJECT_ID', ''),
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                    "client_secret": self.client_secret,
                    "redirect_uris": [callback_url],
                }
            }

            # Create flow with enhanced security measures
            try:
                flow = Flow.from_client_config(
                    oauth_config,
                    scopes=self.SCOPES,
                    redirect_uri=callback_url
                )
            except Exception as flow_error:
                error_msg = f"Failed to create OAuth flow: {str(flow_error)}"
                logger.error(error_msg)
                raise ValueError(error_msg)

            # Comprehensive flow validation
            if not flow.client_config or not isinstance(flow.client_config, dict):
                raise ValueError("Invalid OAuth flow configuration structure")
                
            required_keys = {
                'client_id', 'client_secret', 'auth_uri', 'token_uri', 
                'redirect_uris'
            }
            config_section = flow.client_config.get('installed', {})
            missing_keys = required_keys - set(config_section.keys())
            if missing_keys:
                raise ValueError(f"OAuth flow configuration missing required fields: {missing_keys}")

            logger.info("OAuth2.0 flow created and validated successfully")
            return flow
            
        except ValueError as e:
            error_msg = f"OAuth configuration error: {str(e)}"
            logger.error(error_msg)
            raise ValueError(error_msg)
            
        except Exception as e:
            error_msg = f"Unexpected error creating OAuth flow: {str(e)}"
            logger.error(error_msg)
            raise ConnectionError(error_msg)

    def store_credentials(self, credentials: Dict[str, Any], user_id: int) -> None:
        """Store OAuth credentials in Neo4j."""
        try:
            # Validate required credential fields
            required_fields = ['token', 'refresh_token', 'token_uri', 'client_id', 'client_secret', 'scopes']
            missing_fields = [field for field in required_fields if field not in credentials]
            if missing_fields:
                raise ValueError(f"Missing required credential fields: {', '.join(missing_fields)}")

            with self.neo4j_driver.session() as session:
                session.execute_write(self._save_credentials, user_id, credentials)
                logger.info(f"Successfully stored credentials for user {user_id}")
        except (neo4j.exceptions.ServiceUnavailable, neo4j.exceptions.AuthError) as e:
            logger.error(f"Neo4j connection error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error storing credentials: {str(e)}")
            raise

    def _save_credentials(self, tx, user_id: int, credentials: Dict[str, Any]) -> None:
        """Neo4j transaction to save credentials."""
        query = """
        MERGE (u:User {id: $user_id})
        SET u.credentials = $credentials
        """
        tx.run(query, user_id=user_id, credentials=credentials)

    def get_iam_data(self, credentials: Credentials) -> Dict[str, Any]:
        """Retrieve IAM data from Google Cloud."""
        try:
            service = build('cloudresourcemanager', 'v1', credentials=credentials)
            
            # Get IAM policies
            request = service.projects().getIamPolicy(
                resource='projects/' + os.environ.get('GOOGLE_PROJECT_ID', ''),
                body={}
            )
            response = request.execute()
            
            return response
            
        except Exception as e:
            logger.error(f"Error retrieving IAM data: {str(e)}")
            return {"error": str(e)}

    def get_asset_inventory(self, credentials: Credentials) -> Dict[str, Any]:
        """Retrieve Cloud Asset Inventory data."""
        try:
            client = asset_v1.AssetServiceClient(credentials=credentials)
            
            parent = f"projects/{os.environ.get('GOOGLE_PROJECT_ID', '')}"
            
            # List assets
            request = asset_v1.ListAssetsRequest(
                parent=parent,
                asset_types=['compute.googleapis.com/Instance']
            )
            
            response = client.list_assets(request)
            assets = []
            
            for asset in response:
                assets.append({
                    "name": asset.name,
                    "type": asset.asset_type,
                    "resource": asset.resource
                })
                
            return {"assets": assets}
            
        except Exception as e:
            logger.error(f"Error retrieving asset inventory: {str(e)}")
            return {"error": str(e)}

    def close(self):
        """Close Neo4j connection."""
        self.neo4j_driver.close()

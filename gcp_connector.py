import os
import time
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.cloud import asset_v1
import neo4j
from typing import Optional, Dict, Any, List
import logging
from neo4j.exceptions import ServiceUnavailable, AuthError

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
        """Lazy initialization of Neo4j driver with connection pooling and retry logic."""
        if self._driver is None:
            retry_count = 0
            max_retries = 3
            base_delay = 1  # Base delay in seconds

            while retry_count < max_retries:
                try:
                    # Configure connection pooling
                    self._driver = neo4j.GraphDatabase.driver(
                        self.neo4j_uri,
                        auth=(self.neo4j_user, self.neo4j_password),
                        max_connection_lifetime=3600,  # 1 hour
                        max_connection_pool_size=50,
                        connection_acquisition_timeout=60  # 60 seconds
                    )
                    
                    # Test the connection and verify access
                    with self._driver.session(database="neo4j") as session:
                        session.run("RETURN 1")
                        logger.info("Successfully connected to Neo4j database")
                        
                    # Initialize schema
                    self._initialize_schema()
                    break  # Exit loop if successful
                    
                except neo4j.exceptions.ServiceUnavailable as e:
                    retry_count += 1
                    if retry_count == max_retries:
                        error_msg = f"Failed to connect to Neo4j after {max_retries} attempts: {str(e)}"
                        logger.error(error_msg)
                        raise ConnectionError(error_msg)
                    
                    delay = base_delay * (2 ** (retry_count - 1))  # Exponential backoff
                    logger.warning(f"Neo4j connection attempt {retry_count} failed, retrying in {delay} seconds...")
                    time.sleep(delay)
                    
                except Exception as e:
                    error_msg = f"Failed to initialize Neo4j connection: {str(e)}"
                    logger.error(error_msg)
                    raise ConnectionError(error_msg)
                    
        return self._driver

    def _initialize_schema(self):
        """Initialize Neo4j database schema with constraints and indexes."""
        with self.neo4j_driver.session() as session:
            try:
                # Create constraints
                session.run("""
                    CREATE CONSTRAINT user_id IF NOT EXISTS
                    FOR (u:User) REQUIRE u.id IS UNIQUE
                """)
                session.run("""
                    CREATE CONSTRAINT iam_policy_name IF NOT EXISTS
                    FOR (p:IAMPolicy) REQUIRE p.name IS UNIQUE
                """)
                session.run("""
                    CREATE CONSTRAINT asset_name IF NOT EXISTS
                    FOR (a:Asset) REQUIRE a.name IS UNIQUE
                """)
                logger.info("Neo4j schema initialized successfully")
            except Exception as e:
                logger.error(f"Error initializing Neo4j schema: {str(e)}")
                raise

    def create_oauth_flow(self, redirect_uri: str = None) -> Flow:
        """Create OAuth2.0 flow for Google authentication with enhanced validation.
        
        Args:
            redirect_uri: Optional override for redirect URI. If not provided,
                        uses the configured callback URL from environment.
        
        Returns:
            Flow: Configured OAuth2.0 flow object
            
        Raises:
            ValueError: If client credentials are invalid or misconfigured
            ConnectionError: If unable to validate credentials
        """
        try:
            # Validate OAuth credentials
            if not self.client_id or len(self.client_id) < 20:
                raise ValueError("Invalid Google client ID format")
            if not self.client_secret or len(self.client_secret) < 10:
                raise ValueError("Invalid Google client secret format")

            # Get callback URL with validation
            callback_url = os.environ.get('OAUTH_CALLBACK_URL', 'https://access-bot-ai-t020.id.repl.co/auth/google/callback')
            if redirect_uri:
                if not redirect_uri.startswith(('http://', 'https://')):
                    raise ValueError("Invalid redirect URI format - must be HTTPS or HTTP")
                logger.warning(f"Overriding default callback URL with: {redirect_uri}")
                callback_url = redirect_uri

            # Validate scopes
            if not isinstance(self.SCOPES, list) or not all(isinstance(s, str) for s in self.SCOPES):
                raise ValueError("Invalid OAuth scopes configuration")

            # Create OAuth config with validation
            oauth_config = {
                "web": {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [callback_url]
                }
            }

            # Create and validate flow
            flow = Flow.from_client_config(
                oauth_config,
                scopes=self.SCOPES,
                redirect_uri=callback_url
            )

            # Verify flow configuration
            if not flow.client_config or not flow.client_config.get('web'):
                raise ValueError("Invalid OAuth flow configuration")

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

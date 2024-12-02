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
        """Initialize Neo4j database schema with constraints and indexes with retry logic."""
        max_retries = 3
        base_delay = 1  # Base delay in seconds
        retry_count = 0
        last_error = None

        while retry_count < max_retries:
            try:
                with self.neo4j_driver.session() as session:
                    # Test database connectivity first
                    session.run("RETURN 1")

                    # Create constraints with proper error handling
                    constraints = [
                        ("user_id", "User", "id"),
                        ("iam_policy_name", "IAMPolicy", "name"),
                        ("asset_name", "Asset", "name")
                    ]

                    for constraint_name, label, property_name in constraints:
                        try:
                            session.run(f"""
                                CREATE CONSTRAINT {constraint_name} IF NOT EXISTS
                                FOR (n:{label}) REQUIRE n.{property_name} IS UNIQUE
                            """)
                            logger.info(f"Successfully created/verified constraint: {constraint_name}")
                        except Exception as e:
                            error_msg = f"Error creating constraint {constraint_name}: {str(e)}"
                            logger.error(error_msg)
                            raise ValueError(error_msg)

                    # Verify constraints were created
                    result = session.run("SHOW CONSTRAINTS")
                    constraints_list = [record["name"] for record in result]
                    logger.info(f"Active constraints: {', '.join(constraints_list)}")
                    
                    logger.info("Neo4j schema initialization completed successfully")
                    return  # Success, exit the retry loop
                    
            except (neo4j.exceptions.ServiceUnavailable, neo4j.exceptions.DatabaseError) as e:
                retry_count += 1
                last_error = str(e)
                
                if retry_count == max_retries:
                    error_msg = f"Failed to initialize Neo4j schema after {max_retries} attempts. Last error: {last_error}"
                    logger.error(error_msg)
                    raise ConnectionError(error_msg)
                
                delay = base_delay * (2 ** (retry_count - 1))  # Exponential backoff
                logger.warning(f"Schema initialization attempt {retry_count} failed, retrying in {delay} seconds...")
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
            # Validate OAuth credentials
            if not self.client_id or len(self.client_id) < 20:
                error_msg = "Invalid Google client ID format or missing client ID"
                logger.error(error_msg)
                raise ValueError(error_msg)
                
            if not self.client_secret or len(self.client_secret) < 10:
                error_msg = "Invalid Google client secret format or missing client secret"
                logger.error(error_msg)
                raise ValueError(error_msg)

            # Build dynamic callback URL
            if not request_host:
                error_msg = "Request host is required for dynamic callback URL"
                logger.error(error_msg)
                raise ValueError(error_msg)
                
            if not request_host.startswith(('http://', 'https://')):
                error_msg = "Invalid request host format - must include protocol (http:// or https://)"
                logger.error(error_msg)
                raise ValueError(error_msg)
                
            callback_url = f"{request_host}/auth/google/callback"
            logger.info(f"Using dynamic callback URL: {callback_url}")

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

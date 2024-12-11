import os
import uuid
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.cloud import asset_v1
from typing import Optional, Dict, Any, List
import logging
from graph_schema import GraphSchema

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
        self.client_id = os.environ.get('GOOGLE_CLIENT_ID')
        self.client_secret = os.environ.get('GOOGLE_CLIENT_SECRET')
        self.graph = GraphSchema()
        
        # Initialize schema
        self.graph.init_schema()

    def create_oauth_flow(self, redirect_uri: str) -> Flow:
        """Create OAuth2.0 flow for Google authentication."""
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            },
            scopes=self.SCOPES,
            redirect_uri=redirect_uri
        )
        return flow

    def store_credentials(self, credentials: Dict[str, Any], user_id: int) -> None:
        """Store OAuth credentials in Neo4j."""
        with self.neo4j_driver.session() as session:
            session.execute_write(self._save_credentials, user_id, credentials)

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

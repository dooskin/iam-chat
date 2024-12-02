import os
import json
from typing import Optional, Dict, Any
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from neo4j import GraphDatabase
from flask import current_app, session
import logging

logger = logging.getLogger(__name__)

class GCPConnector:
    """Handles Google Cloud Platform authentication and API interactions."""
    
    SCOPES = [
        'https://www.googleapis.com/auth/cloud-platform.read-only',
        'https://www.googleapis.com/auth/cloud-identity.groups.readonly',
    ]
    
    def __init__(self):
        self.credentials: Optional[Credentials] = None
        
    def create_authorization_url(self, redirect_uri: str) -> str:
        """Create OAuth 2.0 authorization URL."""
        try:
            client_config = {
                "web": {
                    "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                    "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            }
            
            flow = Flow.from_client_config(
                client_config,
                scopes=self.SCOPES,
                redirect_uri=redirect_uri
            )
            
            auth_url, _ = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true'
            )
            
            return auth_url
            
        except Exception as e:
            logger.error(f"Error creating authorization URL: {str(e)}")
            raise
            
    def get_credentials_from_code(self, code: str, redirect_uri: str) -> Credentials:
        """Exchange authorization code for credentials."""
        try:
            client_config = {
                "web": {
                    "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                    "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            }
            
            flow = Flow.from_client_config(
                client_config,
                scopes=self.SCOPES,
                redirect_uri=redirect_uri
            )
            
            flow.fetch_token(code=code)
            return flow.credentials
            
        except Exception as e:
            logger.error(f"Error getting credentials from code: {str(e)}")
            raise
            
    def store_credentials(self, credentials: Credentials) -> None:
        """Store credentials in session."""
        session['gcp_token'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes,
        }
        
    def load_credentials(self) -> Optional[Credentials]:
        """Load credentials from session."""
        if 'gcp_token' not in session:
            return None
            
        token_data = session['gcp_token']
        return Credentials(
            token=token_data['token'],
            refresh_token=token_data['refresh_token'],
            token_uri=token_data['token_uri'],
            client_id=token_data['client_id'],
            client_secret=token_data['client_secret'],
            scopes=token_data['scopes'],
        )
        
    def get_project_info(self) -> Dict[str, Any]:
        """Get current GCP project information."""
        try:
            credentials = self.load_credentials()
            if not credentials:
                raise ValueError("No credentials available")
                
            service = build('cloudresourcemanager', 'v1', credentials=credentials)
            
            # Get first accessible project
            request = service.projects().list()
            response = request.execute()
            
            if not response.get('projects'):
                raise ValueError("No accessible projects found")
                
            project = response['projects'][0]
            return {
                'project_id': project['projectId'],
                'name': project['name'],
                'number': project['projectNumber'],
            }
            
        except Exception as e:
            logger.error(f"Error getting project info: {str(e)}")
            raise

class Neo4jConnector:
    """Handles Neo4j database connections and operations."""
    
    def __init__(self):
        self.driver = None
        
    def connect(self, uri: str, user: str, password: str) -> bool:
        """Establish connection to Neo4j database."""
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            # Verify connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            return True
        except Exception as e:
            logger.error(f"Neo4j connection error: {str(e)}")
            self.driver = None
            return False
            
    def close(self):
        """Close the database connection."""
        if self.driver:
            self.driver.close()
            
    def store_connection_info(self, uri: str, user: str) -> None:
        """Store connection information in session."""
        session['neo4j_connection'] = {
            'uri': uri,
            'user': user,
            'connected': True
        }
        
    def is_connected(self) -> bool:
        """Check if Neo4j is connected."""
        return 'neo4j_connection' in session and session['neo4j_connection'].get('connected', False)
        
    def get_connection_info(self) -> Dict[str, str]:
        """Get stored connection information."""
        if 'neo4j_connection' not in session:
            return {'uri': '', 'user': ''}
        return {
            'uri': session['neo4j_connection'].get('uri', ''),
            'user': session['neo4j_connection'].get('user', '')
        }

# Initialize connectors
gcp_connector = GCPConnector()
neo4j_connector = Neo4jConnector()

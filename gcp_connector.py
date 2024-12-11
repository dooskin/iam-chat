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
        """
        Retrieve comprehensive IAM data from Google Cloud.
        Includes: IAM policies, service accounts, and roles.
        """
        try:
            service = build('cloudresourcemanager', 'v1', credentials=credentials)
            iam_service = build('iam', 'v1', credentials=credentials)
            project_id = os.environ.get('GOOGLE_PROJECT_ID', '')
            project_path = f'projects/{project_id}'
            
            # Get project IAM policies
            policy_request = service.projects().getIamPolicy(
                resource=project_path,
                body={'options': {'requestedPolicyVersion': 3}}
            )
            policy_response = policy_request.execute()
            
            # Get service accounts
            sa_request = iam_service.projects().serviceAccounts().list(
                name=project_path
            )
            sa_response = sa_request.execute()
            
            # Get custom roles
            roles_request = iam_service.projects().roles().list(
                parent=project_path
            )
            roles_response = roles_request.execute()
            
            # Structure data for Neo4j ingestion
            iam_data = {
                'policies': policy_response.get('bindings', []),
                'serviceAccounts': sa_response.get('accounts', []),
                'customRoles': roles_response.get('roles', []),
                'metadata': {
                    'projectId': project_id,
                    'etag': policy_response.get('etag', ''),
                    'version': policy_response.get('version', 1)
                }
            }
            
            # Store in Neo4j using GraphSchema
            self._store_iam_data(iam_data)
            
            return iam_data
            
        except Exception as e:
            logger.error(f"Error retrieving IAM data: {str(e)}")
            return {"error": str(e)}

    def get_asset_inventory(self, credentials: Credentials) -> Dict[str, Any]:
        """
        Retrieve comprehensive Cloud Asset Inventory data.
        Includes: Compute instances, storage buckets, networks, and other GCP resources.
        """
        try:
            client = asset_v1.AssetServiceClient(credentials=credentials)
            project_id = os.environ.get('GOOGLE_PROJECT_ID', '')
            parent = f"projects/{project_id}"
            
            # Define asset types to collect
            asset_types = [
                'compute.googleapis.com/Instance',
                'compute.googleapis.com/Network',
                'compute.googleapis.com/Subnetwork',
                'compute.googleapis.com/Firewall',
                'storage.googleapis.com/Bucket',
                'container.googleapis.com/Cluster',
                'cloudkms.googleapis.com/CryptoKey'
            ]
            
            assets = []
            for asset_type in asset_types:
                try:
                    # List assets of specific type
                    request = asset_v1.ListAssetsRequest(
                        parent=parent,
                        asset_types=[asset_type],
                        content_type=asset_v1.ContentType.RESOURCE
                    )
                    
                    response = client.list_assets(request)
                    
                    for asset in response:
                        processed_asset = {
                            "id": asset.name.split('/')[-1],
                            "name": asset.name,
                            "type": asset.asset_type,
                            "platform": "GCP",
                            "metadata": {
                                "project_id": project_id,
                                "location": asset.resource.location if hasattr(asset.resource, 'location') else None,
                                "state": asset.resource.data.get('status', None) if hasattr(asset.resource, 'data') else None,
                                "labels": asset.resource.data.get('labels', {}) if hasattr(asset.resource, 'data') else {},
                                "creation_timestamp": asset.resource.data.get('creationTimestamp', None) if hasattr(asset.resource, 'data') else None,
                                "raw_resource": asset.resource.data if hasattr(asset.resource, 'data') else {}
                            }
                        }
                        assets.append(processed_asset)
                        
                except Exception as type_error:
                    logger.warning(f"Error collecting assets of type {asset_type}: {str(type_error)}")
                    continue
            
            # Store assets in Neo4j
            self._store_assets(assets)
            
            return {"assets": assets}
            
        except Exception as e:
            logger.error(f"Error retrieving asset inventory: {str(e)}")
            return {"error": str(e)}

    def _store_iam_data(self, iam_data: Dict[str, Any]) -> None:
        """Store IAM data in Neo4j using GraphSchema with enhanced Cartography compatibility."""
        try:
            project_id = iam_data['metadata']['projectId']
            
            # Create project node with Cartography metadata
            project_data = {
                'id': f"project_{project_id}",
                'name': project_id,
                'type': 'GCPProject',
                'platform': 'GCP',
                'metadata': {
                    **iam_data['metadata'],
                    'resource_type': 'cloudresourcemanager.googleapis.com/Project',
                    'asset_type': 'google.cloud.Project'
                },
                'environment': 'production',
                'tags': ['gcp', 'project'],
                'relationships': []
            }
            self.graph.create_or_update_asset(project_data)
            
            # Process service accounts with enhanced metadata
            for sa in iam_data['serviceAccounts']:
                sa_data = {
                    'id': sa['uniqueId'],
                    'email': sa['email'],
                    'name': sa['displayName'],
                    'type': 'ServiceAccount',
                    'platform': 'GCP',
                    'metadata': {
                        'projectId': project_id,
                        'disabled': sa.get('disabled', False),
                        'oauth2ClientId': sa.get('oauth2ClientId', ''),
                        'resource_type': 'iam.googleapis.com/ServiceAccount',
                        'asset_type': 'google.cloud.ServiceAccount',
                        'email_address': sa['email'],
                        'unique_id': sa['uniqueId']
                    },
                    'environment': 'production',
                    'tags': ['gcp', 'service-account'],
                    'relationships': [{
                        'target_id': f"project_{project_id}",
                        'type': 'BELONGS_TO'
                    }]
                }
                self.graph.create_or_update_asset(sa_data)
                
                # Create embeddings for service account metadata
                self.graph.create_node_embedding(
                    sa_data['id'],
                    'ServiceAccount',
                    f"Service Account {sa_data['name']} ({sa_data['email']}) in project {project_id}"
                )
            
            # Process IAM policies with enhanced relationship mapping
            for binding in iam_data['policies']:
                role_name = binding['role'].split('/')[-1]
                role_data = {
                    'id': f"role_{role_name}",
                    'name': role_name,
                    'type': 'Role',
                    'platform': 'GCP',
                    'metadata': {
                        'fullPath': binding['role'],
                        'members': binding['members'],
                        'resource_type': 'iam.googleapis.com/Role',
                        'asset_type': 'google.cloud.Role'
                    },
                    'environment': 'production',
                    'tags': ['gcp', 'iam', 'role'],
                    'relationships': [{
                        'target_id': f"project_{project_id}",
                        'type': 'BELONGS_TO'
                    }]
                }
                self.graph.create_or_update_asset(role_data)
                
                # Create embeddings for role metadata
                self.graph.create_node_embedding(
                    role_data['id'],
                    'Role',
                    f"IAM Role {role_data['name']} in project {project_id} with members {', '.join(binding['members'])}"
                )
                
                # Process role bindings and create relationships
                for member in binding['members']:
                    member_type, member_id = member.split(':')
                    if member_type == 'serviceAccount':
                        # Create relationship between role and service account
                        rel_data = {
                            'source_id': role_data['id'],
                            'target_id': member_id.split('@')[0],  # Extract SA unique ID
                            'type': 'HAS_ACCESS'
                        }
                        role_data['relationships'].append(rel_data)
            
            logger.info(f"Successfully stored IAM data for project {project_id} with enhanced Cartography compatibility")
            
        except Exception as e:
            logger.error(f"Error storing IAM data: {str(e)}")
            logger.error("Stack trace:", exc_info=True)
            raise

    def close(self):
        """Close the graph schema connection."""
        self.graph.close()

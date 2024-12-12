import os
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from graph_schema import GraphSchema
from gcp_connector import GCPConnector

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CartographySync:
    """Handles data synchronization with Cartography compatibility."""
    
    def __init__(self):
        """Initialize connections and interfaces."""
        self.graph = GraphSchema()
        self.gcp = GCPConnector()
        
    def sync_gcp_resources(self, credentials: Any) -> None:
        """
        Synchronize GCP resources with Cartography-compatible schema.
        
        Args:
            credentials: GCP credentials object
        """
        try:
            logger.info("Starting GCP resource synchronization with Cartography schema...")
            
            # Fetch GCP data using existing connector
            iam_data = self.gcp.get_iam_data(credentials)
            asset_data = self.gcp.get_asset_inventory(credentials)
            
            if "error" in iam_data or "error" in asset_data:
                raise ValueError("Error fetching GCP data")
            
            # Process IAM data with Cartography schema
            self._process_iam_data(iam_data)
            
            # Process Asset Inventory with Cartography schema
            self._process_asset_data(asset_data)
            
            logger.info("Successfully synchronized GCP resources with Cartography schema")
            
        except Exception as e:
            logger.error(f"Error synchronizing GCP resources: {str(e)}")
            raise
            
    def _process_iam_data(self, iam_data: Dict[str, Any]) -> None:
        """Process IAM data with Cartography schema compatibility."""
        try:
            # Create project node (root asset)
            project_data = {
                'id': f"gcp_project_{iam_data['metadata']['projectId']}",
                'name': iam_data['metadata']['projectId'],
                'type': 'GCPProject',
                'platform': 'GCP',
                'metadata': {
                    'etag': iam_data['metadata']['etag'],
                    'resource_type': 'cloudresourcemanager.googleapis.com/Project'
                },
                'environment': 'production',
                'relationships': []
            }
            self.graph.create_or_update_asset(project_data)
            
            # Process service accounts
            for sa in iam_data['serviceAccounts']:
                sa_data = {
                    'id': sa['uniqueId'],
                    'name': sa['displayName'],
                    'type': 'ServiceAccount',
                    'platform': 'GCP',
                    'metadata': {
                        'email': sa['email'],
                        'oauth2ClientId': sa.get('oauth2ClientId', ''),
                        'resource_type': 'iam.googleapis.com/ServiceAccount'
                    },
                    'relationships': [{
                        'target_id': project_data['id'],
                        'type': 'BELONGS_TO'
                    }]
                }
                self.graph.create_or_update_asset(sa_data)
                
                # Create embeddings for service account
                self.graph.create_node_embedding(
                    sa_data['id'],
                    'ServiceAccount',
                    f"Service Account {sa_data['name']} ({sa_data['metadata']['email']}) in project {project_data['name']}"
                )
            
            # Process IAM roles and bindings
            for binding in iam_data['policies']:
                role_name = binding['role'].split('/')[-1]
                role_data = {
                    'id': f"role_{role_name}",
                    'name': role_name,
                    'type': 'Role',
                    'platform': 'GCP',
                    'metadata': {
                        'fullPath': binding['role'],
                        'resource_type': 'iam.googleapis.com/Role'
                    },
                    'relationships': [{
                        'target_id': project_data['id'],
                        'type': 'BELONGS_TO'
                    }]
                }
                self.graph.create_or_update_asset(role_data)
                
                # Create role embeddings
                self.graph.create_node_embedding(
                    role_data['id'],
                    'Role',
                    f"IAM Role {role_data['name']} in project {project_data['name']}"
                )
                
        except Exception as e:
            logger.error(f"Error processing IAM data: {str(e)}")
            raise
            
    def _process_asset_data(self, asset_data: Dict[str, Any]) -> None:
        """Process Cloud Asset Inventory data with Cartography schema compatibility."""
        try:
            assets = asset_data.get('assets', [])
            current_time = int(datetime.utcnow().timestamp())
            
            for asset in assets:
                # Determine Cartography asset type and relationship
                asset_type = asset['type'].split('/')[-1]
                cartography_type = self._get_cartography_type(asset_type)
                relationship_type = self._get_relationship_type(asset_type)
                
                # Convert GCP asset to Cartography-compatible format
                processed_asset = {
                    'id': asset['id'],
                    'name': asset.get('name', ''),
                    'type': cartography_type,
                    'platform': 'GCP',
                    'metadata': {
                        'resource_type': asset['type'],
                        'location': asset.get('metadata', {}).get('location'),
                        'state': asset.get('metadata', {}).get('state'),
                        'labels': asset.get('metadata', {}).get('labels', {}),
                        'creation_timestamp': asset.get('metadata', {}).get('creation_timestamp'),
                        'cartography_sync_type': 'FULL',
                        'cartography_sync_time': current_time,
                        'last_ingested': current_time,
                        'source': 'cloud-asset-inventory',
                        'raw_data': asset.get('metadata', {}).get('raw_resource', {})
                    },
                    'relationships': [{
                        'target_id': f"gcp_project_{asset.get('metadata', {}).get('project_id')}",
                        'type': relationship_type,
                        'properties': {
                            'lastupdated': current_time,
                            'source': 'cloud-asset-inventory'
                        }
                    }]
                }
                
                # Create or update asset in graph
                self.graph.create_or_update_asset(processed_asset)
                
                # Create asset embeddings
                self.graph.create_node_embedding(
                    processed_asset['id'],
                    processed_asset['type'],
                    f"{processed_asset['type']} {processed_asset['name']} in project {asset.get('metadata', {}).get('project_id')}",
                    processed_asset['metadata']
                )
                
        except Exception as e:
            logger.error(f"Error processing asset data: {str(e)}")
            raise
            
    def close(self):
        """Clean up connections."""
        try:
            self.graph.close()
            self.gcp.close()
        except Exception as e:
            logger.error(f"Error closing connections: {str(e)}")

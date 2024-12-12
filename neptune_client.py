import os
import json
import logging
import boto3
from botocore.config import Config
from datetime import datetime
from typing import Dict, List, Optional, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NeptuneClient:
    """AWS Neptune client using boto3 Data API."""
    
    def __init__(self):
        """Initialize Neptune client with boto3."""
        try:
            self.region = os.getenv('AWS_REGION', 'us-east-2')
            self.endpoint = os.getenv('NEPTUNE_ENDPOINT')
            if not self.endpoint:
                raise ValueError("NEPTUNE_ENDPOINT environment variable is required")
                
            # Configure boto3 client with retry logic
            config = Config(
                region_name=self.region,
                retries={
                    'max_attempts': 3,
                    'mode': 'standard'
                }
            )
            
            # Initialize Neptune client
            self.client = boto3.client(
                'neptune-db',
                region_name=self.region,
                endpoint_url=f'https://{self.endpoint}:8182',
                config=config
            )
            
            logger.info(f"Initialized Neptune client for endpoint: {self.endpoint}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Neptune client: {str(e)}")
            raise
            
    def execute_query(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute a Gremlin query using Neptune Data API."""
        try:
            request = {
                'gremlin': query
            }
            if parameters:
                request['parameters'] = parameters
                
            response = self.client.execute_gremlin(
                query=json.dumps(request)
            )
            
            return response['result']
            
        except Exception as e:
            logger.error(f"Query execution failed: {str(e)}")
            logger.error(f"Query: {query}")
            if parameters:
                logger.error(f"Parameters: {parameters}")
            raise
            
    def create_vertex(self, label: str, properties: Dict[str, Any]) -> str:
        """Create a vertex with given label and properties."""
        try:
            # Prepare vertex creation query
            property_strings = [
                f".property('{k}', {json.dumps(v)})" for k, v in properties.items()
            ]
            query = f"g.addV('{label}')" + ''.join(property_strings)
            
            result = self.execute_query(query)
            vertex_id = result['data'][0]['id']
            
            logger.info(f"Created vertex with ID: {vertex_id}")
            return vertex_id
            
        except Exception as e:
            logger.error(f"Failed to create vertex: {str(e)}")
            raise
            
    def create_edge(self, from_id: str, to_id: str, label: str, properties: Optional[Dict[str, Any]] = None) -> str:
        """Create an edge between vertices."""
        try:
            # Base query for edge creation
            query = f"g.V('{from_id}').addE('{label}').to(g.V('{to_id}')"
            
            # Add properties if provided
            if properties:
                property_strings = [
                    f".property('{k}', {json.dumps(v)})" for k, v in properties.items()
                ]
                query += ''.join(property_strings)
            
            query += ")"
            
            result = self.execute_query(query)
            edge_id = result['data'][0]['id']
            
            logger.info(f"Created edge with ID: {edge_id}")
            return edge_id
            
        except Exception as e:
            logger.error(f"Failed to create edge: {str(e)}")
            raise
            
    def get_vertices(self, label: Optional[str] = None, properties: Optional[Dict[str, Any]] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get vertices with optional filtering."""
        try:
            query = "g.V()"
            if label:
                query += f".hasLabel('{label}')"
                
            if properties:
                for k, v in properties.items():
                    query += f".has('{k}', {json.dumps(v)})"
                    
            query += f".limit({limit})"
            
            result = self.execute_query(query)
            return result['data']
            
        except Exception as e:
            logger.error(f"Failed to get vertices: {str(e)}")
            raise
            
    def get_vertex_neighbors(self, vertex_id: str, direction: str = 'both', edge_label: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get neighboring vertices of a given vertex."""
        try:
            query = f"g.V('{vertex_id}')"
            
            if direction == 'out':
                query += ".out()"
            elif direction == 'in':
                query += ".in()"
            else:
                query += ".both()"
                
            if edge_label:
                query += f"('{edge_label}')"
                
            query += f".limit({limit})"
            
            result = self.execute_query(query)
            return result['data']
            
        except Exception as e:
            logger.error(f"Failed to get vertex neighbors: {str(e)}")
            raise
            
    def delete_vertex(self, vertex_id: str) -> None:
        """Delete a vertex and its edges."""
        try:
            query = f"g.V('{vertex_id}').drop()"
            self.execute_query(query)
            logger.info(f"Deleted vertex: {vertex_id}")
            
        except Exception as e:
            logger.error(f"Failed to delete vertex: {str(e)}")
            raise

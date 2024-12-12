import os
import json
import time
import logging
import boto3
import requests
from botocore.config import Config
from datetime import datetime
from typing import Dict, List, Optional, Any
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NeptuneClient:
    """AWS Neptune client using boto3 Data API."""
    
    def __init__(self):
        """Initialize Neptune client with boto3 and IAM authentication."""
        try:
            # Get configuration from environment
            self.region = os.getenv('AWS_REGION', 'us-east-2')
            self.endpoint = os.getenv('NEPTUNE_ENDPOINT')
            if not self.endpoint:
                raise ValueError("NEPTUNE_ENDPOINT environment variable is required")
            
            logger.info(f"Initializing Neptune client in region {self.region}")
            
            # Configure AWS credentials
            self.session = boto3.Session(region_name=self.region)
            credentials = self.session.get_credentials()
            
            if not credentials:
                raise ValueError("AWS credentials not found. Please configure AWS credentials.")
            
            # Store credentials for request signing
            self.credentials = credentials.get_frozen_credentials()
            
            # Set up the Neptune endpoint URL
            self.neptune_endpoint = f"wss://{self.endpoint}:8182/gremlin"
            
            # Configure retry settings
            self.config = Config(
                region_name=self.region,
                retries={
                    'max_attempts': 3,
                    'mode': 'standard'
                }
            )
            
            # Initialize standard Neptune client for metadata operations
            self.client = boto3.client(
                'neptune',
                region_name=self.region,
                config=self.config
            )
            
            # Verify VPC endpoint configuration
            self._verify_vpc_endpoint()
            
            logger.info(f"Initialized Neptune client for endpoint: {self.endpoint}")
            self._test_connection()
            
        except Exception as e:
            logger.error(f"Failed to initialize Neptune client: {str(e)}")
            raise
            
    def _verify_vpc_endpoint(self):
        """Verify Neptune VPC endpoint configuration and connectivity."""
        try:
            # Get VPC ID where this application is running
            ec2 = boto3.client('ec2', region_name=self.region)
            
            # First check for Neptune service endpoint in the region
            neptune = boto3.client('neptune', region_name=self.region)
            try:
                neptune.describe_db_engine_versions(Engine='neptune')
                logger.info("✓ Neptune service is available in region %s", self.region)
            except Exception as e:
                logger.error("✗ Neptune service not available in region %s", self.region)
                logger.error("Please verify Neptune is supported in your region")
                raise
            
            # Check for Neptune VPC endpoints
            response = ec2.describe_vpc_endpoints(
                Filters=[{
                    'Name': 'service-name', 
                    'Values': [f'com.amazonaws.{self.region}.neptune-db']
                }]
            )
            
            if not response['VpcEndpoints']:
                logger.warning("\n🔸 Neptune VPC Endpoint Configuration Required:")
                logger.warning("----------------------------------------")
                logger.warning("No Neptune VPC endpoints found in region %s", self.region)
                logger.warning("\n1️⃣  Create an Interface VPC Endpoint:")
                logger.warning("   • Service: com.amazonaws.%s.neptune-db", self.region)
                logger.warning("   • Type: Interface")
                logger.warning("   • VPC: Your application VPC")
                logger.warning("\n2️⃣  Configure Security Group Rules:")
                logger.warning("   • Inbound Rule 1: TCP 8182 (Neptune API/WebSocket)")
                logger.warning("   • Source: Application Security Group")
                logger.warning("\n3️⃣  Required IAM Permissions:")
                logger.warning("   • Action: neptune-db:*")
                logger.warning("   • Resource: Your Neptune cluster ARN")
                logger.warning("\n4️⃣  DNS Configuration:")
                logger.warning("   • Enable DNS hostnames in VPC")
                logger.warning("   • Enable DNS resolution in VPC")
                
            else:
                logger.info("\n🔹 Neptune VPC Endpoint Status:")
                logger.info("----------------------------------------")
                logger.info("Found %d VPC endpoint(s)", len(response['VpcEndpoints']))
                
                for endpoint in response['VpcEndpoints']:
                    endpoint_id = endpoint.get('VpcEndpointId', 'Unknown')
                    vpc_id = endpoint.get('VpcId', 'Unknown')
                    state = endpoint.get('State', 'Unknown')
                    subnet_ids = [subnet.get('SubnetId', 'Unknown') 
                                for subnet in endpoint.get('SubnetIds', [])]
                    security_groups = endpoint.get('Groups', [])
                    
                    logger.info("\n📍 Endpoint Configuration:")
                    logger.info("• ID: %s", endpoint_id)
                    logger.info("• VPC: %s", vpc_id)
                    logger.info("• State: %s", state)
                    logger.info("• Subnets: %s", ', '.join(subnet_ids))
                    logger.info("• Security Groups: %s", 
                              ', '.join([sg.get('GroupId', 'Unknown') for sg in security_groups]))
                    
                    if state != 'available':
                        logger.warning("\n⚠️  Warning: Endpoint %s is not in 'available' state", endpoint_id)
                        logger.warning("Please check the endpoint configuration in AWS Console")
                    else:
                        logger.info("\n✅ Endpoint is available and properly configured")
                        
                        # Test DNS resolution
                        try:
                            import socket
                            socket.gethostbyname(self.endpoint)
                            logger.info("✅ DNS resolution successful for Neptune endpoint")
                        except Exception as dns_error:
                            logger.warning("⚠️  DNS resolution failed: %s", str(dns_error))
                            logger.warning("Please verify DNS settings in your VPC")
                    
        except Exception as e:
            logger.error("\n❌ VPC Endpoint Verification Failed:")
            logger.error("----------------------------------------")
            logger.error("Error: %s", str(e))
            logger.error("\nTroubleshooting Steps:")
            logger.error("1. Verify IAM permissions include:")
            logger.error("   - ec2:DescribeVpcEndpoints")
            logger.error("   - neptune:DescribeDBEngineVersions")
            logger.error("2. Confirm Neptune service availability")
            logger.error("3. Check VPC configurations")
            raise
            
    def _test_connection(self):
        """Test the Neptune connection by making a simple query."""
        retry_count = 0
        max_retries = 3
        last_error = None

        while retry_count < max_retries:
            try:
                logger.info(f"Testing connection (attempt {retry_count + 1}/{max_retries})...")
                
                # Simple test query
                test_query = "g.V().limit(1).count()"
                response = self.execute_query(test_query)
                logger.info("✓ Successfully tested Neptune connection")
                return True
                
            except Exception as e:
                retry_count += 1
                last_error = str(e)
                
                if retry_count < max_retries:
                    wait_time = min(2 ** retry_count, 30)
                    logger.warning(f"Connection test failed (attempt {retry_count}/{max_retries}): {last_error}")
                    logger.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    logger.error(f"Connection test failed after {max_retries} attempts")
                    logger.error("Last error: " + last_error)
                    logger.error("\nPlease verify:")
                    logger.error("1. Neptune endpoint is correct and accessible")
                    logger.error("2. VPC endpoint is properly configured")
                    logger.error("3. Security group allows inbound traffic on port 8182")
                    logger.error("4. IAM role has necessary Neptune permissions")
                    raise Exception(f"Failed to establish connection after {max_retries} attempts: {last_error}")
            
    def execute_query(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute a Gremlin query using Neptune Data API with IAM authentication."""
        try:
            # Prepare the request payload with query timeout
            payload = {
                'gremlin': query,
                'timeout': 30000  # 30 seconds timeout in milliseconds
            }
            if parameters:
                payload['bindings'] = parameters
                
            # Convert payload to JSON with proper error handling
            try:
                request_data = json.dumps(payload)
            except Exception as e:
                raise ValueError(f"Failed to serialize query payload: {str(e)}")
            
            # Create the main request with SigV4 authentication
            request = AWSRequest(
                method='POST',
                url=self.neptune_endpoint,
                data=request_data,
                headers={
                    'Content-Type': 'application/json',
                    'Host': self.endpoint,
                    'Connection': 'keep-alive',
                    'x-amz-date': datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
                }
            )
            
            # Sign the request with IAM credentials
            try:
                SigV4Auth(self.credentials, 'neptune-db', self.region).add_auth(request)
            except Exception as e:
                raise RuntimeError(f"Failed to sign request with IAM credentials: {str(e)}")
            
            # Create and sign WebSocket upgrade request
            ws_request = AWSRequest(
                method='GET',
                url=self.neptune_endpoint,
                headers={
                    'host': self.endpoint,
                    'connection': 'upgrade',
                    'upgrade': 'websocket',
                    'sec-websocket-version': '13',
                    'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'x-amz-date': datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
                }
            )
            
            try:
                SigV4Auth(self.credentials, 'neptune-db', self.region).add_auth(ws_request)
            except Exception as e:
                raise RuntimeError(f"Failed to sign WebSocket request: {str(e)}")
            
            # Make the HTTP request with proper headers for WebSocket handshake
            try:
                response = requests.post(
                    self.neptune_endpoint.replace('wss://', 'https://'),
                    data=request_data,
                    headers={
                        **dict(ws_request.headers),
                        'Content-Type': 'application/json'
                    },
                    verify=True,
                    timeout=30
                )
            except requests.exceptions.RequestException as e:
                raise ConnectionError(f"Failed to connect to Neptune endpoint: {str(e)}")
            
            # Handle HTTP errors with detailed messages
            if response.status_code != 200:
                error_message = f"Query failed with status {response.status_code}"
                try:
                    error_details = response.json()
                    if isinstance(error_details, dict):
                        error_message += f": {error_details.get('message', response.text)}"
                except:
                    error_message += f": {response.text}"
                raise Exception(error_message)
            
            # Parse and validate response
            try:
                result = response.json()
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to parse Neptune response: {str(e)}")
            
            # Check for query execution errors
            if 'errors' in result and result['errors']:
                error_details = result['errors']
                if isinstance(error_details, list):
                    error_message = '; '.join(str(error) for error in error_details)
                else:
                    error_message = str(error_details)
                raise Exception(f"Query execution failed: {error_message}")
                
            return result
            
        except Exception as e:
            logger.error(f"Query execution failed: {str(e)}")
            logger.error(f"Query: {query}")
            if parameters:
                logger.error(f"Parameters: {parameters}")
            raise
            
    def create_edge(self, from_vertex_id: str, to_vertex_id: str, label: str, properties: Optional[Dict[str, Any]] = None) -> str:
        """Create an edge between two vertices with given label and properties."""
        try:
            # Prepare edge creation query with properties
            property_strings = []
            if properties:
                property_strings = [
                    f".property('{k}', {json.dumps(v)})" 
                    for k, v in properties.items()
                ]
            
            # Build the query with proper error handling for vertex existence
            query = f"""
                g.V('{from_vertex_id}').as('from')
                .V('{to_vertex_id}').as('to')
                .coalesce(
                    __.select('from').outE('{label}').where(__.inV().is(__.select('to'))),
                    __.select('from').addE('{label}').to(__.select('to')){(''.join(property_strings))}
                )
            """.strip()
            
            result = self.execute_query(query)
            
            if not result.get('data'):
                raise ValueError("Failed to create or find edge between vertices")
                
            edge_id = result['data'][0]['id']
            logger.info(f"Created edge with ID: {edge_id}")
            return edge_id
            
        except Exception as e:
            logger.error(f"Failed to create edge: {str(e)}")
            logger.error(f"From vertex: {from_vertex_id}")
            logger.error(f"To vertex: {to_vertex_id}")
            logger.error(f"Label: {label}")
            if properties:
                logger.error(f"Properties: {properties}")
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

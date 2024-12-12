import os
import ssl
import logging
import json
import boto3
import asyncio
import aiohttp
from datetime import datetime
from botocore.config import Config
from gremlin_python.driver.driver_remote_connection import DriverRemoteConnection
from gremlin_python.process.anonymous_traversal import traversal
from gremlin_python.process.graph_traversal import __
from gremlin_python.driver.protocol import GremlinServerError
from gremlin_python.driver import serializer
from gremlin_python.driver.aiohttp.transport import AiohttpTransport
from aiohttp.client_exceptions import ClientConnectorError, ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def verify_endpoint_format(endpoint: str) -> bool:
    """Verify if the endpoint follows Neptune naming convention and check VPC access."""
    try:
        # Verify endpoint format
        parts = endpoint.split('.')
        if len(parts) < 4:
            return False
        if not all(parts):  # Check for empty parts
            return False
        if 'neptune' not in parts or 'amazonaws' not in parts:
            return False
            
        # Verify VPC endpoint access
        try:
            region = os.getenv('AWS_REGION', 'us-east-2')
            ec2 = boto3.client('ec2', region_name=region)
            
            # Check VPC endpoints
            response = ec2.describe_vpc_endpoints(
                Filters=[
                    {'Name': 'service-name', 'Values': [f'com.amazonaws.{region}.neptune-db']}
                ]
            )
            
            if not response['VpcEndpoints']:
                logger.warning("No Neptune VPC endpoints found. This may cause connection issues.")
                logger.warning("Please ensure VPC endpoints are properly configured.")
            else:
                logger.info("Found Neptune VPC endpoint configuration")
                for endpoint in response['VpcEndpoints']:
                    logger.info(f"VPC Endpoint ID: {endpoint.get('VpcEndpointId')}")
                    logger.info(f"VPC ID: {endpoint.get('VpcId')}")
                    logger.info(f"State: {endpoint.get('State')}")
            
        except Exception as vpc_error:
            logger.warning(f"Unable to verify VPC endpoints: {str(vpc_error)}")
            logger.warning("This may be due to insufficient IAM permissions")
            
        return True
    except Exception:
        return False

def get_neptune_version(endpoint: str) -> str:
    """Get Neptune engine version using boto3."""
    try:
        region = os.getenv('AWS_REGION', 'us-east-2')
        logger.info(f"Initializing Neptune client in region: {region}")
        
        neptune = boto3.client('neptune', 
                             region_name=region,
                             config=Config(retries={'max_attempts': 3}))
        
        # Extract cluster identifier from endpoint
        cluster_id = endpoint.split('.')[0]
        logger.info(f"Querying cluster information for: {cluster_id}")
        
        response = neptune.describe_db_clusters(
            Filters=[{'Name': 'db-cluster-id', 'Values': [cluster_id]}]
        )
        
        if response['DBClusters']:
            version = response['DBClusters'][0]['EngineVersion']
            logger.info(f"Found Neptune cluster version: {version}")
            return version
            
        logger.warning("No Neptune clusters found matching the provided identifier")
        return "Unknown"
        
    except Exception as e:
        logger.error(f"Error retrieving Neptune version: {str(e)}")
        return "Unknown"

def test_neptune_connection():
    """Test AWS Neptune connection and basic graph operations."""
    connection = None
    try:
        logger.info("=== Starting Neptune Connection Test ===")
        
        # Get and validate Neptune endpoint
        endpoint = os.getenv('NEPTUNE_ENDPOINT')
        if not endpoint:
            raise ValueError("NEPTUNE_ENDPOINT environment variable is required")
        
        logger.info("\n=== Endpoint Validation ===")
        logger.info(f"• Endpoint provided: {endpoint}")
        
        if not verify_endpoint_format(endpoint):
            raise ValueError(f"Invalid endpoint format: {endpoint}\n" +
                           "Expected format: [cluster-name].[cluster-id].[region].neptune.amazonaws.com")
        logger.info("✓ Endpoint format validation passed")
        
        # Verify Neptune version
        version = get_neptune_version(endpoint)
        logger.info(f"• Neptune Engine Version: {version}")
        
        logger.info("\n=== Testing Connectivity ===")
        
        # Initialize Gremlin connection with improved error handling
        retry_count = 0
        max_retries = 3
        
        while retry_count < max_retries:
            try:
                logger.info(f"\nAttempt {retry_count + 1} of {max_retries}")
                
                # Configure SSL context
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = True
                ssl_context.verify_mode = ssl.CERT_REQUIRED

                # Initialize connection with progressive timeouts
                logger.info(f"Initializing connection to Neptune at wss://{endpoint}:8182/gremlin")
                logger.info("Configuring connection parameters...")
                
                # Start with shorter timeouts for initial attempt
                initial_timeout = 15
                connection = DriverRemoteConnection(
                    f'wss://{endpoint}:8182/gremlin',
                    'g',
                    message_serializer=serializer.GraphSONSerializersV2d0(),
                    transport_factory=lambda: AiohttpTransport(
                        call_from_event_loop=True,
                        read_timeout=initial_timeout,
                        write_timeout=initial_timeout,
                        ssl=ssl_context,
                        verify_ssl=True
                    )
                )
                
                logger.info("Connection object created, establishing remote connection...")
                # Create traversal source
                g = traversal().withRemote(connection)
                logger.info("Remote traversal source created successfully")
                
                # Test connection with progressive queries
                logger.info("Testing connection with simple queries...")
                
                # First test: Simple vertex count
                logger.info("Step 1: Testing vertex count query...")
                count = g.V().limit(1).count().next()
                logger.info(f"✓ Basic query successful (found {count} vertices)")
                
                # Second test: Schema information
                logger.info("Step 2: Retrieving vertex labels...")
                labels = g.V().label().dedup().toList()
                logger.info(f"✓ Schema query successful (found labels: {labels})")
                
                logger.info("All connection tests passed successfully")
                
                # Clean up and close connection
                if connection:
                    connection.close()
                
                logger.info("\n=== Neptune Connection Test Completed Successfully ===")
                return True
                
            except (GremlinServerError, ClientConnectorError) as e:
                retry_count += 1
                logger.error(f"Neptune connection error (attempt {retry_count}/{max_retries})")
                logger.error(f"Error type: {type(e).__name__}")
                logger.error(f"Error details: {str(e)}")
                
                if isinstance(e, ClientConnectorError):
                    logger.error("This may indicate VPC connectivity issues:")
                    logger.error("- Check if your instance is in the correct VPC")
                    logger.error("- Verify security group allows inbound on port 8182")
                    logger.error("- Confirm VPC endpoints are properly configured")
                
                if retry_count < max_retries:
                    wait_time = min(2 ** retry_count, 30)
                    logger.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    raise Exception(f"Failed to connect after {max_retries} attempts. Please check VPC and security group configurations.")
                    
            except ssl.SSLError as e:
                logger.error("SSL Certificate verification failed:")
                logger.error(str(e))
                logger.error("Please verify:")
                logger.error("- Neptune SSL certificate is valid")
                logger.error("- Your environment trusts AWS certificates")
                raise
                
            except ClientError as e:
                logger.error("AWS API error encountered:")
                logger.error(str(e))
                logger.error("This may indicate insufficient IAM permissions")
                logger.error("Required permissions: neptune-db:*")
                raise
                    
            except Exception as e:
                logger.error(f"Unexpected error: {str(e)}")
                raise
            finally:
                if connection:
                    try:
                        connection.close()
                    except Exception as close_error:
                        logger.error(f"Error closing connection: {str(close_error)}")
    
    except Exception as e:
        logger.error(f"\n❌ Neptune connection test failed: {str(e)}")
        logger.error("\nPlease verify:")
        logger.error("1. Neptune endpoint is correct and accessible")
        logger.error("2. Security group allows inbound traffic on port 8182")
        logger.error("3. IAM permissions include neptune-db:* actions")
        logger.error("4. VPC and subnet configuration allows access")
        logger.error(f"5. Neptune version is 1.3.2.1 (Current: {version if 'version' in locals() else 'Unknown'})")
        return False

if __name__ == "__main__":
    test_neptune_connection()
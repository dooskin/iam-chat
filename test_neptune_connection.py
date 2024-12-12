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
        logger.info("\n=== Verifying Neptune Endpoint Format ===")
        # Verify endpoint format
        parts = endpoint.split('.')
        if len(parts) < 4:
            logger.error("Invalid endpoint format: insufficient parts")
            logger.error("Expected format: [cluster-name].[cluster-id].[region].neptune.amazonaws.com")
            return False
            
        if not all(parts):  # Check for empty parts
            logger.error("Invalid endpoint format: contains empty parts")
            return False
            
        if 'neptune' not in parts or 'amazonaws' not in parts:
            logger.error("Invalid endpoint format: missing required domains")
            logger.error("Endpoint must contain 'neptune' and 'amazonaws' domains")
            return False
            
        # Extract and verify cluster information
        cluster_name = parts[0]
        cluster_id = parts[1]
        endpoint_region = parts[2]
        
        logger.info("✓ Endpoint Format Valid:")
        logger.info(f"• Cluster Name: {cluster_name}")
        logger.info(f"• Cluster ID: {cluster_id}")
        logger.info(f"• Region: {endpoint_region}")
            
        # Verify VPC endpoint access
        try:
            region = os.getenv('AWS_REGION', 'us-east-2')
            logger.info(f"\n=== Checking VPC Endpoint Configuration in {region} ===")
            
            ec2 = boto3.client('ec2', region_name=region)
            service_name = f'com.amazonaws.{region}.neptune-db'
            
            # Check VPC endpoints
            response = ec2.describe_vpc_endpoints(
                Filters=[{'Name': 'service-name', 'Values': [service_name]}]
            )
            
            if not response['VpcEndpoints']:
                logger.warning("\n⚠️  VPC Endpoint Configuration Required:")
                logger.warning("----------------------------------------")
                logger.warning(f"No Neptune VPC endpoints found for service: {service_name}")
                logger.warning("\nRequired Steps:")
                logger.warning("1. Create an Interface VPC Endpoint:")
                logger.warning(f"   • Service Name: {service_name}")
                logger.warning("   • VPC: Your application VPC")
                logger.warning("2. Configure Security Groups:")
                logger.warning("   • Allow inbound TCP 8182")
                logger.warning("   • Source: Your application security group")
            else:
                logger.info("\n✓ Found VPC Endpoint Configuration:")
                for endpoint in response['VpcEndpoints']:
                    endpoint_id = endpoint.get('VpcEndpointId', 'Unknown')
                    vpc_id = endpoint.get('VpcId', 'Unknown')
                    state = endpoint.get('State', 'Unknown')
                    
                    logger.info(f"\nEndpoint Details:")
                    logger.info(f"• ID: {endpoint_id}")
                    logger.info(f"• VPC: {vpc_id}")
                    logger.info(f"• State: {state}")
                    
                    if state != 'available':
                        logger.warning(f"⚠️  Warning: Endpoint {endpoint_id} state is '{state}'")
                        logger.warning("Please check endpoint configuration in AWS Console")
            
        except Exception as vpc_error:
            logger.warning("\n⚠️  VPC Endpoint Verification Failed:")
            logger.warning(f"Error: {str(vpc_error)}")
            logger.warning("\nPossible causes:")
            logger.warning("1. Insufficient IAM permissions")
            logger.warning("2. Invalid AWS credentials")
            logger.warning("3. Network connectivity issues")
            
        return True
        
    except Exception as e:
        logger.error(f"\n❌ Endpoint Format Verification Failed: {str(e)}")
        return False

def get_neptune_version(endpoint: str) -> str:
    """Get Neptune engine version and cluster details using boto3."""
    try:
        region = os.getenv('AWS_REGION', 'us-east-2')
        logger.info(f"\n=== Querying Neptune Cluster Information ===")
        logger.info(f"• Region: {region}")
        
        # Configure Neptune client with retries
        neptune = boto3.client('neptune', 
                             region_name=region,
                             config=Config(
                                 retries={'max_attempts': 3},
                                 connect_timeout=15,
                                 read_timeout=15
                             ))
        
        # Extract cluster identifier from endpoint
        try:
            cluster_id = endpoint.split('.')[0]
            logger.info(f"• Cluster ID: {cluster_id}")
        except Exception:
            logger.error("Failed to extract cluster ID from endpoint")
            logger.error("Expected format: [cluster-name].[region].neptune.amazonaws.com")
            return "Unknown"
        
        try:
            # Get cluster information
            response = neptune.describe_db_clusters(
                Filters=[{'Name': 'db-cluster-id', 'Values': [cluster_id]}]
            )
            
            if response['DBClusters']:
                cluster = response['DBClusters'][0]
                version = cluster['EngineVersion']
                status = cluster['Status']
                endpoint = cluster.get('Endpoint', 'Not available')
                
                logger.info("\n✓ Neptune Cluster Details:")
                logger.info(f"• Engine Version: {version}")
                logger.info(f"• Status: {status}")
                logger.info(f"• Endpoint: {endpoint}")
                
                # Additional cluster information
                logger.info("\nCluster Configuration:")
                logger.info(f"• Database Name: {cluster.get('DatabaseName', 'default')}")
                logger.info(f"• Port: {cluster.get('Port', 8182)}")
                logger.info(f"• Storage Encrypted: {cluster.get('StorageEncrypted', False)}")
                
                # VPC configuration
                vpc_id = cluster.get('VpcSecurityGroups', [{}])[0].get('VpcId', 'Unknown')
                logger.info(f"• VPC ID: {vpc_id}")
                
                return version
            else:
                logger.warning("\n⚠️  No matching Neptune clusters found")
                logger.warning(f"No clusters found with ID: {cluster_id}")
                logger.warning("Please verify:")
                logger.warning("1. Cluster ID is correct")
                logger.warning("2. Cluster exists in the specified region")
                logger.warning("3. IAM permissions allow cluster access")
                return "Unknown"
            
        except neptune.exceptions.DBClusterNotFoundFault:
            logger.error(f"\n❌ Neptune cluster '{cluster_id}' not found")
            logger.error("Please verify the cluster exists and you have access")
            return "Unknown"
            
    except Exception as e:
        logger.error(f"\n❌ Error retrieving Neptune cluster information:")
        logger.error(f"Error: {str(e)}")
        logger.error("\nTroubleshooting steps:")
        logger.error("1. Verify AWS credentials are correct")
        logger.error("2. Check IAM permissions include:")
        logger.error("   - neptune:DescribeDBClusters")
        logger.error("   - neptune:ListTagsForResource")
        logger.error("3. Confirm Neptune service is available in region")
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
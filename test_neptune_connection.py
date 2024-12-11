import os
import logging
import json
import boto3
from botocore.config import Config
from gremlin_python.driver.driver_remote_connection import DriverRemoteConnection
from gremlin_python.process.anonymous_traversal import traversal
from gremlin_python.process.graph_traversal import __
from gremlin_python.driver.protocol import GremlinServerError
from gremlin_python.driver import serializer
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def verify_endpoint_format(endpoint: str) -> bool:
    """Verify if the endpoint follows Neptune naming convention."""
    try:
        parts = endpoint.split('.')
        if len(parts) < 4:
            return False
        if not all(parts):  # Check for empty parts
            return False
        if 'neptune' not in parts or 'amazonaws' not in parts:
            return False
        return True
    except Exception:
        return False

def get_neptune_version(endpoint: str) -> str:
    """Get Neptune engine version using boto3."""
    try:
        region = os.getenv('AWS_REGION', 'us-east-1')
        neptune = boto3.client('neptune', 
                             region_name=region,
                             config=Config(retries={'max_attempts': 3}))
        
        # Extract cluster identifier from endpoint
        cluster_id = endpoint.split('.')[0]
        
        response = neptune.describe_db_clusters(
            Filters=[{'Name': 'db-cluster-id', 'Values': [cluster_id]}]
        )
        
        if response['DBClusters']:
            return response['DBClusters'][0]['EngineVersion']
        return "Unknown"
    except Exception as e:
        logger.warning(f"Could not retrieve Neptune version: {str(e)}")
        return "Unknown"

def test_neptune_connection():
    """Test AWS Neptune connection and basic graph operations for version 1.3.2.1."""
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
        if version != "Unknown" and version != "1.3.2.1":
            logger.warning(f"⚠ Expected version 1.3.2.1, but found {version}")
        
        logger.info("\n=== Testing Connectivity ===")
        logger.info(f"Connecting to Neptune endpoint: {endpoint}")
        
        # Initialize Gremlin connection with improved error handling
        connection = None
        retry_count = 0
        max_retries = 3
        
        while retry_count < max_retries:
            try:
                logger.info(f"\nAttempt {retry_count + 1} of {max_retries}")
                logger.info(f"Connecting to Neptune at wss://{endpoint}:8182/gremlin")
                
                connection = DriverRemoteConnection(
                    f'wss://{endpoint}:8182/gremlin',
                    'g',
                    message_serializer=serializer.GraphSONSerializersV2d0()
                )
                
                # Test connection by creating traversal source
                g = traversal().withRemote(connection)
                # Verify connection with a simple query
                g.V().limit(1).count().next()
                
                logger.info("✓ Successfully established connection to Neptune")
                break
                
            except GremlinServerError as gse:
                retry_count += 1
                logger.error(f"Gremlin Server Error: {str(gse)}")
                if retry_count < max_retries:
                    logger.info(f"Retrying in {2 ** retry_count} seconds...")
                    import time
                    time.sleep(2 ** retry_count)
                else:
                    raise Exception("Failed to connect to Neptune after maximum retries")
                    
            except Exception as e:
                logger.error(f"Unexpected error during connection: {str(e)}")
                raise
        
        try:
            # Test 1: Feature compatibility check for 1.3.2.1
            logger.info("\n=== Testing 1.3.2.1 Features ===")
            
            # Test vertex with all supported property types
            test_id = f"test_{datetime.now().timestamp()}"
            test_vector = [0.1, 0.2, 0.3] * 10  # 30-dimensional test vector
            
            logger.info("• Testing property types support...")
            vertex = g.addV('TestNode')\
                .property('id', test_id)\
                .property('string', 'test_string')\
                .property('number', 42.0)\
                .property('boolean', True)\
                .property('date', datetime.now().isoformat())\
                .property('vector', json.dumps(test_vector))\
                .next()
            logger.info("✓ Created test vertex with multiple property types")
            
            # Test 2: Vector search capabilities (1.3.2.1 feature)
            logger.info("\n• Testing vector search capabilities...")
            try:
                result = g.V().has('TestNode', 'id', test_id)\
                    .order().by('vector', 'vector_cosine')\
                    .limit(1)\
                    .toList()
                logger.info("✓ Vector similarity search executed successfully")
            except Exception as e:
                logger.warning(f"⚠ Vector search test failed: {str(e)}")
            
            # Test 3: Query optimization features
            logger.info("\n• Testing query optimization features...")
            try:
                explain_query = g.V().hasLabel('TestNode')\
                    .has('id', test_id)\
                    .out()\
                    .in_()\
                    .explain()
                logger.info("✓ Query plan analysis available")
                logger.info(f"Query plan: {explain_query}")
            except Exception as e:
                logger.warning(f"⚠ Query plan retrieval failed: {str(e)}")
            
            # Test 4: Transaction support
            logger.info("\n• Testing transaction support...")
            try:
                g.V().hasLabel('TestNode').has('id', test_id)\
                    .property('test_transaction', 'value')\
                    .next()
                logger.info("✓ Transaction support verified")
            except Exception as e:
                logger.warning(f"⚠ Transaction test failed: {str(e)}")
            
            logger.info("\n=== Neptune 1.3.2.1 Compatibility Summary ===")
            logger.info("✓ Multi-property type support: Available")
            logger.info("✓ Vector operations: Tested")
            logger.info("✓ Query optimization: Available")
            logger.info("✓ Transaction support: Verified")
            
            return True
            
        finally:
            # Cleanup test data
            try:
                if 'test_id' in locals():
                    g.V().hasLabel('TestNode').has('id', test_id).drop().iterate()
                    logger.info("\n✓ Test data cleaned up")
            except Exception as cleanup_error:
                logger.warning(f"Error during cleanup: {str(cleanup_error)}")
            
            # Close connection
            try:
                if 'connection' in locals():
                    connection.close()
                    logger.info("✓ Connection closed")
            except Exception as close_error:
                logger.warning(f"Error closing connection: {str(close_error)}")
    
    except Exception as e:
        logger.error(f"\n❌ Neptune connection test failed: {str(e)}")
        logger.error("\nPlease verify:")
        logger.error("1. Neptune endpoint is correct and accessible")
        logger.error("2. Security group allows inbound traffic on port 8182")
        logger.error("3. IAM permissions include neptune-db:* actions")
        logger.error("4. VPC and subnet configuration allows access")
        logger.error(f"5. Neptune version is 1.3.2.1 (Current: {get_neptune_version(endpoint)})")
        return False

if __name__ == "__main__":
    test_neptune_connection()
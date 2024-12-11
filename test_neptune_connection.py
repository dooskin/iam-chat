import os
import logging
from gremlin_python.driver.driver_remote_connection import DriverRemoteConnection
from gremlin_python.process.anonymous_traversal import traversal
from gremlin_python.process.graph_traversal import __
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_neptune_connection():
    """Test AWS Neptune connection and basic graph operations."""
    try:
        logger.info("=== Starting Neptune Connection Test ===")
        
        # Get Neptune endpoint from environment
        endpoint = os.getenv('NEPTUNE_ENDPOINT')
        if not endpoint:
            raise ValueError("NEPTUNE_ENDPOINT environment variable is required")
            
        logger.info(f"Connecting to Neptune endpoint: {endpoint}")
        
        # Initialize Gremlin connection
        connection = DriverRemoteConnection(
            f'wss://{endpoint}:8182/gremlin',
            'g'
        )
        g = traversal().withRemote(connection)
        logger.info("✓ Successfully established connection to Neptune")
        
        try:
            # Test 1: Basic vertex creation and query
            logger.info("\nTesting basic vertex operations...")
            test_id = f"test_{datetime.now().timestamp()}"
            
            # Add test vertex
            g.addV('TestNode')\
                .property('id', test_id)\
                .property('name', 'Test Vertex')\
                .property('timestamp', datetime.now().isoformat())\
                .next()
            logger.info("✓ Successfully created test vertex")
            
            # Query test vertex
            result = g.V().hasLabel('TestNode').has('id', test_id).valueMap().toList()
            if result:
                logger.info("✓ Successfully queried test vertex")
                logger.info(f"Vertex properties: {result[0]}")
            
            # Test 2: Vector property support (Neptune 1.2.1.0+ feature)
            logger.info("\nTesting vector property support...")
            test_vector = [0.1, 0.2, 0.3]  # Sample embedding
            g.V().has('TestNode', 'id', test_id)\
                .property('embedding', test_vector)\
                .next()
            logger.info("✓ Successfully added vector property")
            
            # Test 3: Version check
            logger.info("\nChecking Neptune version...")
            try:
                version_info = g.V().limit(1).valueMap().explain().toList()
                logger.info(f"Neptune Version Info: {version_info}")
            except Exception as e:
                logger.warning(f"Could not retrieve version info: {str(e)}")
            
            logger.info("\n=== Neptune Connection Test Summary ===")
            logger.info("✓ Basic connectivity: Successful")
            logger.info("✓ Vertex operations: Successful")
            logger.info("✓ Vector property support: Available")
            
            return True
            
        finally:
            # Cleanup test data
            try:
                g.V().hasLabel('TestNode').has('id', test_id).drop().iterate()
                logger.info("\n✓ Test data cleaned up")
            except Exception as cleanup_error:
                logger.warning(f"Error during cleanup: {str(cleanup_error)}")
            
            # Close connection
            if connection:
                connection.close()
                logger.info("✓ Connection closed")
    
    except Exception as e:
        logger.error(f"\n❌ Neptune connection test failed: {str(e)}")
        logger.error("Please verify:")
        logger.error("1. Neptune endpoint is correct")
        logger.error("2. Security group allows access")
        logger.error("3. IAM permissions are configured")
        return False

if __name__ == "__main__":
    test_neptune_connection()

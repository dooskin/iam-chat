import os
import logging
from datetime import datetime
from neptune_client import NeptuneClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_neptune_client():
    """Test the boto3-based Neptune client implementation."""
    try:
        logger.info("=== Starting Neptune Client Test ===")
        
        # Check AWS credentials
        logger.info("\n=== Checking AWS Credentials ===")
        aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
        aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
        aws_region = os.getenv('AWS_REGION')
        neptune_endpoint = os.getenv('NEPTUNE_ENDPOINT')
        
        if not all([aws_access_key, aws_secret_key, aws_region, neptune_endpoint]):
            missing = []
            if not aws_access_key: missing.append('AWS_ACCESS_KEY_ID')
            if not aws_secret_key: missing.append('AWS_SECRET_ACCESS_KEY')
            if not aws_region: missing.append('AWS_REGION')
            if not neptune_endpoint: missing.append('NEPTUNE_ENDPOINT')
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
            
        logger.info("✓ AWS credentials found")
        logger.info(f"• Region: {aws_region}")
        logger.info(f"• Endpoint: {neptune_endpoint}")
        
        # Initialize client
        logger.info("\n=== Initializing Neptune Client ===")
        client = NeptuneClient()
        logger.info("✓ Client initialized successfully")
        
        # Test vertex creation
        logger.info("\n=== Testing Vertex Operations ===")
        test_user = {
            'id': f'test_user_{int(datetime.now().timestamp())}',
            'name': 'Test User',
            'department': 'Engineering',
            'email': 'test@example.com',
            'created_at': datetime.now().isoformat()
        }
        
        logger.info("\n=== Testing Vertex Creation ===")
        vertex_id = client.create_vertex('User', test_user)
        logger.info(f"✓ Created test user vertex with ID: {vertex_id}")
        
        # Test vertex query
        logger.info("\n=== Testing Vertex Query ===")
        vertices = client.get_vertices(
            label='User',
            properties={'id': test_user['id']},
            limit=1
        )
        if vertices:
            logger.info("✓ Successfully retrieved test vertex")
            logger.info(f"Vertex properties: {vertices[0]}")
        else:
            raise Exception("Failed to retrieve test vertex")
            
        # Test edge creation
        test_resource = {
            'id': f'test_resource_{int(datetime.now().timestamp())}',
            'name': 'Test Resource',
            'type': 'S3Bucket',
            'created_at': datetime.now().isoformat()
        }
        
        logger.info("\n=== Testing Edge Creation ===")
        try:
            resource_id = client.create_vertex('Resource', test_resource)
            logger.info(f"✓ Created test resource vertex with ID: {resource_id}")
            
            edge_properties = {
                'permission': 'WRITE',
                'created_at': datetime.now().isoformat(),
                'lastupdated': int(datetime.now().timestamp() * 1000),
                'firstseen': int(datetime.now().timestamp() * 1000)
            }
            
            edge_id = client.create_edge(
                vertex_id,
                resource_id,
                'HAS_ACCESS',
                edge_properties
            )
            logger.info(f"✓ Created test edge with ID: {edge_id}")
            
            # Test neighbor query
            logger.info("\n=== Testing Neighbor Query ===")
            neighbors = client.get_vertex_neighbors(
                vertex_id,
                direction='out',
                edge_label='HAS_ACCESS'
            )
            if neighbors:
                logger.info("✓ Successfully retrieved vertex neighbors")
                logger.info(f"Found {len(neighbors)} neighbors")
                logger.info("Sample neighbor properties:")
                for prop, value in neighbors[0].items():
                    if prop not in ['id', 'label']:
                        logger.info(f"  • {prop}: {value}")
            else:
                raise Exception("Failed to retrieve vertex neighbors")
                
        finally:
            # Clean up test edges (they will be removed with vertex deletion)
            logger.info("\n=== Cleaning Up Test Data ===")
            client.delete_vertex(vertex_id)  # This will also delete connected edges
            client.delete_vertex(resource_id)
            logger.info("✓ Test data cleaned up")
            
        logger.info("\n=== Cleaning Up Test Data ===")
        client.delete_vertex(vertex_id)
        client.delete_vertex(resource_id)
        logger.info("✓ Test data cleaned up")
        
        logger.info("\n=== Neptune Client Test Completed Successfully ===")
        return True
        
    except Exception as e:
        logger.error(f"\n❌ Neptune client test failed: {str(e)}")
        logger.error("\nPlease verify:")
        logger.error("1. AWS credentials are correctly configured")
        logger.error("2. Neptune endpoint is accessible")
        logger.error("3. IAM role has necessary Neptune permissions")
        return False

if __name__ == "__main__":
    test_neptune_client()

import os
import logging
from graph_schema import GraphSchema
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_neo4j_connection():
    """Test Neo4j connection, schema initialization, and validation with Cartography compatibility."""
    try:
        # Initialize GraphSchema with environment variables
        logger.info("Initializing Graph Schema for Cartography integration...")
        logger.info("Using Neo4j configuration from environment variables for secure connection...")
        
        # Verify environment variables
        neo4j_uri = os.environ.get('NEO4J_URI')
        neo4j_user = os.environ.get('NEO4J_USER')
        neo4j_password = os.environ.get('NEO4J_PASSWORD')
        
        if not all([neo4j_uri, neo4j_user, neo4j_password]):
            logger.error("Missing required Neo4j environment variables")
            logger.error(f"NEO4J_URI present: {bool(neo4j_uri)}")
            logger.error(f"NEO4J_USER present: {bool(neo4j_user)}")
            logger.error(f"NEO4J_PASSWORD present: {bool(neo4j_password)}")
            return False
            
        graph = GraphSchema()
        
        # Test connection with retry logic
        logger.info(f"Testing Neo4j connection to {neo4j_uri}...")
        retry_count = 0
        max_retries = 3
        
        while retry_count < max_retries:
            try:
                # Test connection using driver's verify_connectivity method
                graph.driver.verify_connectivity()
                logger.info("Successfully connected to Neo4j")
                break
            except Exception as e:
                retry_count += 1
                if retry_count == max_retries:
                    logger.error(f"Failed to establish Neo4j connection after {max_retries} attempts")
                    logger.error(f"Last error: {str(e)}")
                    raise
                logger.warning(f"Connection attempt {retry_count} failed: {str(e)}. Retrying in {2 ** retry_count} seconds...")
                import time
                time.sleep(2 ** retry_count)  # Exponential backoff
        
        # Initialize and validate schema
        logger.info("Initializing schema...")
        graph.init_schema()
        
        logger.info("Validating schema...")
        if not graph.validate_schema():
            raise Exception("Schema validation failed. Check logs for details.")
        logger.info("Schema validation successful")
        
        # Test basic operations
        test_data = {
            'id': 'test_user_001',
            'email': 'test@example.com',
            'name': 'Test User',
            'title': 'Software Engineer',
            'department': 'Engineering'
        }
        
        try:
            # Create test user node
            logger.info("Testing user node creation...")
            graph.create_or_update_user(test_data)
            logger.info("Successfully created test user node")
            
            # Create test embedding
            logger.info("Testing embedding creation...")
            test_content = "This is a test user who works in engineering"
            graph.create_node_embedding(
                node_id=test_data['id'],
                node_type='User',
                text_content=test_content
            )
            logger.info("Successfully created test embedding")
            
            # Test similarity search
            logger.info("Testing graph context retrieval...")
            similar_nodes = graph.get_graph_context(
                query="Find engineers in the company",
                limit=5
            )
            logger.info(f"Found {len(similar_nodes.get('primary_nodes', []))} similar nodes")
            
        finally:
            # Clean up test data
            logger.info("Cleaning up test data...")
            with graph.driver.session() as session:
                session.run("""
                    MATCH (n:User {id: $id})
                    DETACH DELETE n
                """, id=test_data['id'])
        
        logger.info("All tests completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Test failed: {str(e)}")
        logger.error("Stack trace:", exc_info=True)
        return False
    
if __name__ == "__main__":
    test_neo4j_connection()

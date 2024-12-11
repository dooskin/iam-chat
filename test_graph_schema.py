import os
import logging
from graph_schema import GraphSchema
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_neo4j_connection():
    """Test Neo4j connection and schema initialization."""
    try:
        # Initialize GraphSchema
        logger.info("Initializing Graph Schema...")
        graph = GraphSchema()
        
        # Test connection
        logger.info("Testing Neo4j connection...")
        if not graph.test_connection():
            raise Exception("Failed to connect to Neo4j database")
        
        # Test schema initialization
        logger.info("Initializing schema...")
        graph.init_schema()
        logger.info("Successfully initialized Neo4j schema")
        
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

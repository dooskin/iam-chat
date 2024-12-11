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
        graph = GraphSchema()
        
        # Test connection by initializing schema
        graph.init_schema()
        logger.info("Successfully initialized Neo4j schema")
        
        # Test node creation
        test_data = {
            'id': 'test_user_001',
            'email': 'test@example.com',
            'name': 'Test User',
            'title': 'Software Engineer',
            'department': 'Engineering'
        }
        
        # Create test user node
        graph.create_or_update_user(test_data)
        logger.info("Successfully created test user node")
        
        # Create test embedding
        test_content = "This is a test user who works in engineering"
        graph.create_node_embedding(
            node_id=test_data['id'],
            node_type='User',
            text_content=test_content
        )
        logger.info("Successfully created test embedding")
        
        # Test similarity search
        similar_nodes = graph.get_graph_context(
            query="Find engineers in the company",
            limit=5
        )
        logger.info(f"Found {len(similar_nodes.get('primary_nodes', []))} similar nodes")
        
        # Clean up test data
        with graph.driver.session() as session:
            session.run("""
                MATCH (n:User {id: $id})
                DETACH DELETE n
            """, id=test_data['id'])
            
        logger.info("Test completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Test failed: {str(e)}")
        return False
    
if __name__ == "__main__":
    test_neo4j_connection()

import os
import logging
from datetime import datetime
from graph_db import GraphDB

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_graph_database():
    """Test local graph database functionality."""
    try:
        logger.info("=== Starting Local Graph Database Test ===")
        
        # Initialize GraphDB
        logger.info("Initializing graph database connection...")
        graph = GraphDB()
        
        # Initialize and validate schema
        logger.info("Initializing and validating schema...")
        if not graph.init_schema():
            raise Exception("Failed to initialize schema")
        logger.info("✓ Schema initialized successfully")
        
        # Test data for vector embedding
        test_nodes = [
            {
                'id': 'test_user_001',
                'type': 'User',
                'content': 'Senior software engineer in the cloud infrastructure team',
                'metadata': {
                    'department': 'Engineering',
                    'location': 'San Francisco',
                    'email': 'engineer@example.com',
                    'employee_type': 'FTE',
                    'title': 'Senior Software Engineer'
                }
            },
            {
                'id': 'test_resource_001',
                'type': 'Resource',
                'content': 'Production Kubernetes cluster in US-West region',
                'metadata': {
                    'environment': 'production',
                    'platform': 'GCP',
                    'resource_type': 'gcp_container_cluster',
                    'project_id': 'prod-infrastructure',
                    'region': 'us-west1'
                }
            }
        ]
        
        # Create test nodes with embeddings
        logger.info("Creating test nodes with embeddings...")
        for node in test_nodes:
            graph.create_node_embedding(
                node_id=node['id'],
                node_type=node['type'],
                text_content=node['content'],
                metadata=node['metadata']
            )
        logger.info("✓ Successfully created test nodes with embeddings")
        
        # Test similarity search
        logger.info("Testing similarity search...")
        test_queries = [
            "Find engineers in the cloud team",
            "Show me production resources in GCP"
        ]
        
        for query in test_queries:
            logger.info(f"\nExecuting query: {query}")
            similar_nodes = graph.get_similar_nodes(
                query_text=query,
                limit=5,
                score_threshold=0.6
            )
            
            # Log results
            logger.info(f"Found {len(similar_nodes)} similar nodes")
            for node in similar_nodes:
                logger.info(f"• Node ID: {node['id']}")
                logger.info(f"  Type: {node['label']}")
                logger.info(f"  Score: {node['score']:.3f}")
                logger.info(f"  Content: {node['content']}")
        
        logger.info("\n=== Local Graph Database Test Completed Successfully ===")
        return True
        
    except Exception as e:
        logger.error(f"Test failed: {str(e)}")
        logger.error("Stack trace:", exc_info=True)
        return False
        
    finally:
        # Clean up test data
        if 'graph' in locals():
            try:
                with graph.driver.session() as session:
                    session.run("""
                        MATCH (n)
                        WHERE n.id IN $ids
                        DETACH DELETE n
                    """, ids=[node['id'] for node in test_nodes])
                logger.info("Test data cleaned up")
                graph.close()
            except Exception as e:
                logger.error(f"Error cleaning up test data: {str(e)}")

if __name__ == "__main__":
    test_graph_database()

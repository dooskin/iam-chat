import os
import logging
from datetime import datetime
from graph_schema import GraphSchema

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_graph_rag_system():
    """Test the Graph RAG system implementation."""
    try:
        logger.info("=== Starting Graph RAG System Test ===")
        
        # Initialize GraphSchema
        logger.info("Initializing Graph Schema...")
        graph = GraphSchema()
        
        # Test schema initialization
        logger.info("Testing schema initialization...")
        graph.init_schema()
        
        if not graph.validate_schema():
            raise Exception("Schema validation failed")
        logger.info("✓ Schema initialized successfully")
        
        # Test data for vector embedding
        test_nodes = [
            {
                'id': 'test_user_001',
                'type': 'User',
                'content': 'Senior software engineer in the cloud infrastructure team',
                'metadata': {
                    'department': 'Engineering',
                    'location': 'San Francisco'
                }
            },
            {
                'id': 'test_resource_001',
                'type': 'Resource',
                'content': 'Production Kubernetes cluster in US-West region',
                'metadata': {
                    'environment': 'production',
                    'platform': 'GCP'
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
        
        # Test context retrieval
        logger.info("Testing graph context retrieval...")
        test_queries = [
            "Find engineers in the cloud team",
            "Show me production resources in GCP"
        ]
        
        for query in test_queries:
            logger.info(f"\nExecuting query: {query}")
            context = graph.get_graph_context(
                query=query,
                limit=5,
                min_similarity=0.6,
                max_hops=2
            )
            
            # Log results
            logger.info(f"Found {len(context['primary_nodes'])} primary nodes")
            logger.info(f"Context graph contains {len(context['context_graph']['nodes'])} nodes "
                       f"and {len(context['context_graph']['relationships'])} relationships")
            logger.info(f"Max similarity: {context['metadata']['max_similarity']:.3f}")
            
        logger.info("\n=== Graph RAG System Test Completed Successfully ===")
        return True
        
    except Exception as e:
        logger.error(f"Test failed: {str(e)}")
        logger.error("Stack trace:", exc_info=True)
        return False
    finally:
        # Clean up test data
        try:
            with graph.driver.session() as session:
                session.run("""
                    MATCH (n)
                    WHERE n.id IN $ids
                    DETACH DELETE n
                """, ids=[node['id'] for node in test_nodes])
            logger.info("Test data cleaned up")
        except Exception as e:
            logger.error(f"Error cleaning up test data: {str(e)}")

if __name__ == "__main__":
    test_graph_rag_system()

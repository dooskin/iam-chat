import os
import logging
from datetime import datetime
from vector_store import VectorStore
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_vector_store():
    """Test the Pinecone serverless vector store implementation."""
    try:
        logger.info("=== Starting Vector Store Test ===")
        
        # Initialize vector store
        logger.info("Initializing vector store...")
        vector_store = VectorStore()
        logger.info("✓ Vector store initialized successfully")
        
        # Test data
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
        
        # Test embedding creation and storage
        logger.info("\nTesting embedding creation and storage...")
        for node in test_nodes:
            vector_store.store_embedding(
                node_id=node['id'],
                node_type=node['type'],
                text_content=node['content'],
                metadata=node['metadata']
            )
        logger.info("✓ Successfully stored embeddings")
        
        # Test similarity search
        logger.info("\nTesting similarity search...")
        test_queries = [
            "Find engineers in the cloud team",
            "Show me production resources in GCP"
        ]
        
        for query in test_queries:
            logger.info(f"\nExecuting query: {query}")
            
            # Test single type search
            results = vector_store.search_similar(
                query=query,
                limit=5,
                score_threshold=0.7
            )
            logger.info(f"Found {len(results)} results for general search")
            
            # Test batch search across types
            batch_results = vector_store.batch_search_similar(
                query=query,
                limit_per_type=3,
                score_threshold=0.7
            )
            total_results = sum(len(results) for results in batch_results.values())
            logger.info(f"Found {total_results} results across all types")
            
            # Log some result details
            for node_type, type_results in batch_results.items():
                if type_results:
                    top_result = type_results[0]
                    logger.info(f"\nTop result for {node_type}:")
                    logger.info(f"Node ID: {top_result['node_id']}")
                    logger.info(f"Similarity: {top_result['similarity']:.3f}")
        
        logger.info("\n=== Vector Store Test Completed Successfully ===")
        return True
        
    except Exception as e:
        logger.error(f"Test failed: {str(e)}")
        logger.error("Stack trace:", exc_info=True)
        return False

if __name__ == "__main__":
    try:
        # Load environment variables
        load_dotenv(override=True)
        
        # Check required environment variables
        if not os.getenv('PINECONE_API_KEY'):
            logger.error("PINECONE_API_KEY environment variable is missing")
            exit(1)
            
        # Run test
        success = test_vector_store()
        if success:
            logger.info("Vector store test completed successfully")
            exit(0)
        else:
            logger.error("Vector store test failed")
            exit(1)
            
    except Exception as e:
        logger.error(f"Test execution failed: {str(e)}")
        logger.error("Stack trace:", exc_info=True)
        exit(1)

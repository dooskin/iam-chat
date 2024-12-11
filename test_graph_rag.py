import os
import logging
from datetime import datetime
from graph_schema import GraphSchema

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_graph_rag_system():
    """Test the Graph RAG system with Cartography integration."""
    try:
        logger.info("=== Starting Graph RAG System Test ===")
        
        # Initialize GraphSchema
        logger.info("Initializing Graph Schema...")
        graph = GraphSchema()
        
        # Initialize and validate schema
        logger.info("Initializing and validating schema...")
        if not graph.init_schema():
            raise Exception("Failed to initialize schema")
        if not graph.validate_schema():
            raise Exception("Schema validation failed")
        logger.info("✓ Schema initialized successfully")
        
        # Test data for vector embedding with Cartography compatibility
        test_nodes = [
            {
                'id': 'test_user_001',
                'type': 'User',
                'content': 'Senior software engineer in the cloud infrastructure team',
                'metadata': {
                    'firstseen': datetime.now().isoformat(),
                    'lastupdated': int(datetime.now().timestamp()),
                    'department': 'Engineering',
                    'location': 'San Francisco',
                    'email': 'engineer@example.com',
                    'employee_type': 'FTE',
                    'title': 'Senior Software Engineer',
                    'manager_id': 'test_user_002'
                }
            },
            {
                'id': 'test_resource_001',
                'type': 'Resource',
                'content': 'Production Kubernetes cluster in US-West region',
                'metadata': {
                    'firstseen': datetime.now().isoformat(),
                    'lastupdated': int(datetime.now().timestamp()),
                    'environment': 'production',
                    'platform': 'GCP',
                    'resource_type': 'gcp_container_cluster',
                    'project_id': 'prod-infrastructure',
                    'region': 'us-west1',
                    'service_account': 'kubernetes-sa@prod-infrastructure.iam.gserviceaccount.com'
                }
            },
            {
                'id': 'test_user_002',
                'type': 'User',
                'content': 'Engineering Manager for the Cloud Platform team',
                'metadata': {
                    'firstseen': datetime.now().isoformat(),
                    'lastupdated': int(datetime.now().timestamp()),
                    'department': 'Engineering',
                    'location': 'San Francisco',
                    'email': 'manager@example.com',
                    'employee_type': 'FTE',
                    'title': 'Engineering Manager'
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
        
        # Define relationships between test nodes
        relationships = [
            {
                'start_id': 'test_user_001',
                'end_id': 'test_resource_001',
                'type': 'MANAGES',
                'properties': {
                    'firstseen': datetime.now().isoformat(),
                    'lastupdated': int(datetime.now().timestamp()),
                    'permission_level': 'admin'
                }
            },
            {
                'start_id': 'test_user_001',
                'end_id': 'test_user_002',
                'type': 'REPORTS_TO',
                'properties': {
                    'firstseen': datetime.now().isoformat(),
                    'lastupdated': int(datetime.now().timestamp())
                }
            }
        ]
        
        # Create relationships between test nodes
        logger.info("Creating relationships between test nodes...")
        with graph.driver.session() as session:
            for rel in relationships:
                session.run("""
                    MATCH (a), (b)
                    WHERE a.id = $start_id AND b.id = $end_id
                    CREATE (a)-[r:$type $properties]->(b)
                    RETURN type(r)
                """, 
                start_id=rel['start_id'],
                end_id=rel['end_id'],
                type=rel['type'],
                properties=rel['properties']
                )
        logger.info("✓ Successfully created relationships between nodes")
        
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
                max_hops=2,
                score_threshold=0.6
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
            if graph and 'test_nodes' in locals():
                with graph.driver.session() as session:
                    session.run("""
                        MATCH (n)
                        WHERE n.id IN $ids
                        DETACH DELETE n
                    """, ids=[node['id'] for node in test_nodes])
                logger.info("Test data cleaned up")
            if graph:
                graph.close()
        except Exception as e:
            logger.error(f"Error cleaning up test data: {str(e)}")
            if graph:
                try:
                    graph.close()
                except Exception as cleanup_error:
                    logger.error(f"Error closing graph connection: {str(cleanup_error)}")

if __name__ == "__main__":
    test_graph_rag_system()

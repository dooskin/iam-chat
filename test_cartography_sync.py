import os
import logging
from datetime import datetime
from neo4j import GraphDatabase
from cartography.sync import sync_cmd
from graph_schema import GraphSchema

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_local_setup():
    """Test local development setup components."""
    try:
        # Test Neo4j connection
        logger.info("Testing Neo4j connection...")
        graph = GraphSchema()
        
        # Verify Neo4j connection and schema
        assert graph.validate_schema(), "Schema validation failed"
        logger.info("Neo4j connection and schema validation successful")
        
        # Test Cartography setup
        logger.info("Testing Cartography setup...")
        assert sync_cmd, "Cartography sync command not available"
        logger.info("Cartography import successful")
        
        return True
        
    except Exception as e:
        logger.error(f"Setup test failed: {str(e)}")
        logger.error("Stack trace:", exc_info=True)
        return False
    finally:
        if 'graph' in locals():
            graph.close()

if __name__ == "__main__":
    if test_local_setup():
        logger.info("Local development setup verified successfully")
    else:
        logger.error("Local development setup verification failed")

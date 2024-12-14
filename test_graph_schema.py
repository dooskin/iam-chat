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
                logger.warning(f"Connection attempt {retry_count} failed: {str(e)}. Retrying...")
                import time
                time.sleep(2 ** retry_count)  # Exponential backoff
        
        # Initialize schema
        logger.info("Initializing schema...")
        graph.init_schema()
        logger.info("Schema initialization completed")
        
        return True
        
    except Exception as e:
        logger.error(f"Test failed: {str(e)}")
        logger.error("Stack trace:", exc_info=True)
        return False
    
if __name__ == "__main__":
    test_neo4j_connection()
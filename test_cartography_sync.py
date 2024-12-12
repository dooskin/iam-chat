import os
import logging
from datetime import datetime
from neo4j import GraphDatabase
from cartography.intel.gcp import sync_gcp_resources
from cartography.sync import sync_cmd

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_neo4j_connection():
    """Test Neo4j connection and basic operations."""
    uri = os.environ.get('NEO4J_URI', 'bolt://localhost:7687')
    user = os.environ.get('NEO4J_USER', 'neo4j')
    password = os.environ.get('NEO4J_PASSWORD', 'password')

    try:
        logger.info(f"Testing Neo4j connection to {uri}")
        driver = GraphDatabase.driver(uri, auth=(user, password))
        
        # Verify connection
        with driver.session() as session:
            result = session.run("RETURN 1 as test")
            test_value = result.single()['test']
            assert test_value == 1, "Basic query test failed"
            
        logger.info("Successfully connected to Neo4j")
        return True
        
    except Exception as e:
        logger.error(f"Neo4j connection test failed: {str(e)}")
        logger.error("Stack trace:", exc_info=True)
        return False

def test_cartography_setup():
    """Test Cartography basic setup."""
    try:
        logger.info("Testing Cartography setup...")
        
        # Test if Cartography modules are properly imported
        assert sync_gcp_resources, "GCP sync module not available"
        assert sync_cmd, "Cartography sync command not available"
        
        logger.info("Cartography modules successfully imported")
        return True
        
    except Exception as e:
        logger.error(f"Cartography setup test failed: {str(e)}")
        logger.error("Stack trace:", exc_info=True)
        return False

if __name__ == "__main__":
    neo4j_test = test_neo4j_connection()
    cartography_test = test_cartography_setup()
    
    if neo4j_test and cartography_test:
        logger.info("All tests passed successfully")
    else:
        logger.error("Some tests failed")

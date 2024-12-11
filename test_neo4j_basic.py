import os
import logging
from neo4j import GraphDatabase
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_basic_connection():
    """Test basic Neo4j connection with minimal complexity."""
    try:
        # Load environment variables
        load_dotenv()
        
        # Get Neo4j credentials
        uri = os.getenv('NEO4J_URI')
        user = os.getenv('NEO4J_USERNAME')
        password = os.getenv('NEO4J_PASSWORD')
        
        logger.info("Testing Neo4j connection with these parameters:")
        logger.info(f"URI: {uri}")
        logger.info(f"Username present: {bool(user)}")
        logger.info(f"Password present: {bool(password)}")
        
        # Create driver instance
        driver = GraphDatabase.driver(
            uri,
            auth=(user, password),
            max_connection_lifetime=3600,
            max_connection_pool_size=50
        )
        
        # Test connection with a simple query
        with driver.session() as session:
            # Run a simple query that doesn't require any specific data
            result = session.run("RETURN 1 as num")
            record = result.single()
            if record and record["num"] == 1:
                logger.info("✓ Successfully connected to Neo4j and ran test query")
                return True
            else:
                logger.error("✗ Failed to get expected result from test query")
                return False
                
    except Exception as e:
        logger.error(f"✗ Connection test failed: {str(e)}")
        logger.error("Stack trace:", exc_info=True)
        return False
    finally:
        try:
            driver.close()
            logger.info("Neo4j driver closed successfully")
        except Exception as e:
            logger.error(f"Error closing driver: {str(e)}")

if __name__ == "__main__":
    test_basic_connection()

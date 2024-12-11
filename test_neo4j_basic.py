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
        # Force reload environment variables
        load_dotenv(override=True)
        
        # Get Neo4j credentials
        uri = os.getenv('NEO4J_URI')
        user = os.getenv('NEO4J_USER')  # Changed to match .env file
        password = os.getenv('NEO4J_PASSWORD')
        
        logger.info("Testing Neo4j connection with these parameters:")
        # Only log the protocol and host structure, not the actual URI
        if uri:
            protocol = uri.split('://')[0] if '://' in uri else 'unknown'
            host = uri.split('://')[1] if '://' in uri else 'unknown'
            logger.info(f"Protocol: {protocol}")
            logger.info(f"Host Structure: {host}")
            logger.info("Expected format: <protocol>://<instance-id>.databases.neo4j.io")
        
        if not all([uri, user, password]):
            logger.error("Missing required Neo4j credentials")
            return False

        # Configure driver with Aura-specific settings
        try:
            logger.info("Initializing Neo4j driver...")
            driver = GraphDatabase.driver(
                uri,
                auth=(user, password),
                max_connection_lifetime=3600,  # 1 hour max connection lifetime
                max_connection_pool_size=50,   # Recommended pool size for Aura
                connection_timeout=30,         # Reduced timeout for faster failure detection
                connection_acquisition_timeout=60
            )
            
            # Verify connectivity explicitly
            logger.info("Verifying driver connectivity...")
            driver.verify_connectivity()
            logger.info("✓ Driver connectivity verified")
            
            # Test connection with a simple query
            logger.info("Testing query execution...")
            with driver.session() as session:
                result = session.run("RETURN 1 as num")
                record = result.single()
                if record and record["num"] == 1:
                    logger.info("✓ Successfully executed test query")
                    return True
                else:
                    logger.error("✗ Failed to get expected result from test query")
                    return False
                    
        except Exception as e:
            logger.error(f"✗ Connection error: {str(e)}")
            # Log additional connection details for debugging
            if 'Cannot resolve address' in str(e):
                logger.error("DNS resolution failed. Please verify the Neo4j URI is correct.")
            elif 'authentication failure' in str(e).lower():
                logger.error("Authentication failed. Please verify username and password.")
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

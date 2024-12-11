import os
import logging
from neo4j import GraphDatabase
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def verify_connection():
    """Simple Neo4j connection verification."""
    try:
        # Load environment variables
        load_dotenv()
        
        # Get connection details
        uri = os.getenv('NEO4J_URI')
        username = os.getenv('NEO4J_USERNAME')
        password = os.getenv('NEO4J_PASSWORD')
        
        # Log configuration (without exposing sensitive data)
        logger.info("Connection Configuration:")
        logger.info(f"URI configured: {bool(uri)}")
        if uri:
            protocol = uri.split('://')[0] if '://' in uri else 'unknown'
            logger.info(f"Protocol: {protocol}")
        logger.info(f"Username configured: {bool(username)}")
        logger.info(f"Password configured: {bool(password)}")
        
        # Create driver with minimal configuration
        # Create driver with Aura-specific configuration
        driver = GraphDatabase.driver(
            uri,
            auth=(username, password),
            max_connection_lifetime=3600,  # 1 hour max connection lifetime
            max_connection_pool_size=50,   # Recommended pool size for Aura
            connection_timeout=30,         # Reduced timeout for faster failure detection
            connection_acquisition_timeout=60
        )
        
        # Verify connectivity (this will actually try to connect)
        logger.info("Attempting to verify connectivity...")
        driver.verify_connectivity()
        logger.info("✓ Successfully connected to Neo4j")
        
        # Try a simple query
        with driver.session() as session:
            result = session.run("RETURN 1 AS num")
            value = result.single()["num"]
            logger.info(f"✓ Successfully executed test query, received: {value}")
            
        return True
        
    except Exception as e:
        logger.error(f"✗ Connection failed: {str(e)}")
        return False
        
    finally:
        try:
            driver.close()
            logger.info("Driver closed")
        except:
            pass

if __name__ == "__main__":
    verify_connection()

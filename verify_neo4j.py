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
    """Verify Neo4j Aura connection with detailed logging and enhanced error handling."""
    driver = None
    try:
        # Load environment variables with explicit logging
        load_dotenv()
        logger.info("Loading Neo4j connection parameters...")
        
        # Get connection details
        uri = os.getenv('NEO4J_URI')
        username = os.getenv('NEO4J_USERNAME')
        password = os.getenv('NEO4J_PASSWORD')
        instance_id = uri.split('://')[1].split('.')[0] if uri else None
        
        # Validate connection parameters with detailed logging
        logger.info("=== Neo4j Connection Validation ===")
        
        # Check and validate URI
        if not uri:
            raise ValueError("NEO4J_URI environment variable is missing")
        logger.info("✓ NEO4J_URI is present")
        
        # Validate URI format and structure
        expected_uri = f"neo4j+s://{instance_id}.databases.neo4j.io"
        if uri != expected_uri:
            logger.error(f"❌ URI mismatch. Current: {uri}")
            logger.error(f"❌ Expected: {expected_uri}")
            raise ValueError(f"Invalid Neo4j URI format. Expected {expected_uri}")
        logger.info(f"✓ URI format is correct: {expected_uri}")
        
        # Validate username
        if not username:
            raise ValueError("NEO4J_USERNAME environment variable is missing")
        if username != 'neo4j':
            raise ValueError("Invalid username. Expected 'neo4j' for Aura instances")
        logger.info("✓ Username validation passed")
        
        # Validate password presence
        if not password:
            raise ValueError("NEO4J_PASSWORD environment variable is missing")
        logger.info("✓ Password is present")
        
        logger.info("\n=== Initializing Neo4j Driver ===")
        logger.info(f"• Instance ID: {instance_id}")
        logger.info("• Connection Settings:")
        logger.info("  - Max Connection Lifetime: 3600s")
        logger.info("  - Pool Size: 50")
        logger.info("  - Connection Timeout: 30s")
        logger.info("  - Acquisition Timeout: 60s")
        
        # Initialize driver with Aura-specific configuration
        driver = GraphDatabase.driver(
            uri,
            auth=(username, password),
            max_connection_lifetime=3600,        # 1 hour max connection lifetime
            max_connection_pool_size=50,         # Recommended for Aura
            connection_timeout=30,               # 30 seconds connection timeout
            connection_acquisition_timeout=60,    # 60 seconds acquisition timeout
            keep_alive=True                      # Enable keep-alive
        )
        
        logger.info("\n=== Testing Connectivity ===")
        
        # Test basic connectivity
        logger.info("• Step 1: Verifying basic connectivity...")
        driver.verify_connectivity()
        logger.info("✓ Basic connectivity test passed")
        
        # Execute test queries with retry logic
        max_retries = 3
        retry_count = 0
        last_error = None
        
        logger.info("• Step 2: Executing test queries...")
        while retry_count < max_retries:
            try:
                with driver.session() as session:
                    # Test basic query
                    result = session.run("RETURN 1 AS num")
                    value = result.single()["num"]
                    logger.info("✓ Basic query test passed")
                    
                    # Test server version
                    result = session.run("CALL dbms.components() YIELD name, versions RETURN name, versions[0] as version")
                    component = result.single()
                    logger.info(f"✓ Neo4j Server Version: {component['name']} {component['version']}")
                    
                    # Test database access and capabilities
                    result = session.run("""
                        CALL db.info()
                        YIELD name, type, address, currentStatus
                        RETURN name, type, address, currentStatus
                    """)
                    db_info = result.single()
                    logger.info("=== Database Information ===")
                    logger.info(f"• Name: {db_info['name']}")
                    logger.info(f"• Type: {db_info['type']}")
                    logger.info(f"• Address: {db_info['address']}")
                    logger.info(f"• Status: {db_info['currentStatus']}")
                    
                    # Additional connectivity verification
                    result = session.run("""
                        CALL dbms.components()
                        YIELD name, versions, edition
                        RETURN name, versions[0] as version, edition
                    """)
                    component = result.single()
                    logger.info("\n=== Neo4j Component Information ===")
                    logger.info(f"• Component: {component['name']}")
                    logger.info(f"• Version: {component['version']}")
                    logger.info(f"• Edition: {component['edition']}")
                    
                    break  # All tests passed
                    
            except Exception as e:
                retry_count += 1
                last_error = str(e)
                if retry_count < max_retries:
                    logger.warning(f"Attempt {retry_count} failed: {last_error}")
                    logger.info(f"Retrying in {2 ** retry_count} seconds...")
                    import time
                    time.sleep(2 ** retry_count)  # Exponential backoff
                else:
                    logger.error(f"❌ All {max_retries} connection attempts failed")
                    logger.error(f"❌ Last error: {last_error}")
                    raise Exception(f"Failed to establish stable connection after {max_retries} attempts")
        
        logger.info("\n=== Connection Verification Complete ===")
        logger.info("✓ All connectivity tests passed successfully")
        return True
        
    except Exception as e:
        logger.error("\n=== Connection Verification Failed ===")
        logger.error(f"❌ Error: {str(e)}")
        logger.error("Please verify:")
        logger.error("1. Neo4j Aura credentials are correct")
        logger.error("2. Network connectivity is available")
        logger.error("3. Instance ID matches: a9902166")
        return False
        
    finally:
        if driver:
            driver.close()
            logger.info("\n=== Cleanup ===")
            logger.info("✓ Neo4j driver connection closed")

if __name__ == "__main__":
    verify_connection()

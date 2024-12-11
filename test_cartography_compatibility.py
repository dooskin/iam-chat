import os
import logging
from neo4j import GraphDatabase
from datetime import datetime
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_cartography_compatibility():
    """Test Neo4j instance compatibility with Cartography requirements."""
    driver = None
    try:
        # Load environment variables
        load_dotenv()
        logger.info("=== Starting Cartography Compatibility Test ===")
        
        # Get connection details
        uri = os.getenv('NEO4J_URI')
        username = os.getenv('NEO4J_USERNAME')
        password = os.getenv('NEO4J_PASSWORD')
        
        if not all([uri, username, password]):
            raise ValueError("Missing required Neo4j configuration")
        
        # Initialize driver with Cartography-specific configuration
        driver = GraphDatabase.driver(
            uri,
            auth=(username, password),
            max_connection_lifetime=3600,
            max_connection_pool_size=50
        )
        
        # Test basic connectivity
        logger.info("Testing basic connectivity...")
        driver.verify_connectivity()
        logger.info("✓ Basic connectivity test passed")
        
        with driver.session() as session:
            # Test 1: Check Neo4j version compatibility
            logger.info("\nChecking Neo4j version...")
            result = session.run("CALL dbms.components() YIELD name, versions, edition")
            component = result.single()
            version = component['versions'][0]
            edition = component['edition']
            logger.info(f"✓ Neo4j Version: {version}")
            logger.info(f"✓ Edition: {edition}")
            
            # Test 2: Verify APOC procedures availability
            logger.info("\nChecking APOC procedures availability...")
            try:
                procedures = session.run("""
                    CALL dbms.procedures()
                    YIELD name
                    WHERE name STARTS WITH 'apoc'
                    RETURN collect(name) as apoc_procedures
                """).single()
                
                if procedures and procedures['apoc_procedures']:
                    logger.info(f"✓ Found {len(procedures['apoc_procedures'])} APOC procedures")
                else:
                    logger.warning("⚠ No APOC procedures found - Cartography may have limited functionality")
            except Exception as e:
                logger.warning(f"⚠ Could not verify APOC procedures: {str(e)}")
            
            # Test 3: Check index capabilities
            logger.info("\nTesting index capabilities...")
            try:
                # Test vector index support
                session.run("""
                    CREATE VECTOR INDEX test_vector_idx IF NOT EXISTS
                    FOR (n:TestNode)
                    ON (n.embedding)
                    OPTIONS {
                        indexConfig: {
                            `vector.dimensions`: 1536,
                            `vector.similarity_function`: 'cosine'
                        }
                    }
                """)
                logger.info("✓ Vector index support verified")
            except Exception as e:
                logger.warning(f"⚠ Vector index limitation: {str(e)}")
            
            # Test 4: Verify write permissions
            logger.info("\nTesting write permissions...")
            try:
                # Create test node
                session.run("""
                    CREATE (n:CartographyTest {
                        id: 'test_node',
                        firstseen: $timestamp,
                        lastupdated: $timestamp
                    })
                """, timestamp=int(datetime.now().timestamp()))
                logger.info("✓ Write permissions verified")
                
                # Clean up test node
                session.run("MATCH (n:CartographyTest) DELETE n")
            except Exception as e:
                logger.error(f"⚠ Write permission error: {str(e)}")
            
            # Test 5: Check memory and storage limits
            logger.info("\nChecking database limits...")
            try:
                result = session.run("CALL dbms.cluster.overview()").single()
                if result:
                    logger.info(f"✓ Cluster configuration available")
            except Exception as e:
                logger.warning("⚠ Could not retrieve cluster information - limited to single instance")
            
            logger.info("\n=== Cartography Compatibility Summary ===")
            logger.info("Required capabilities for Cartography:")
            logger.info(f"1. Neo4j Version: {version} {'✓' if float(version.split('.')[0]) >= 4.4 else '✗'}")
            logger.info(f"2. Edition: {edition} {'✓' if 'enterprise' in edition.lower() or float(version.split('.')[0]) >= 5 else '⚠'}")
            logger.info("3. APOC Procedures: " + ("✓" if procedures and procedures['apoc_procedures'] else "✗"))
            logger.info("4. Vector Index Support: " + ("✓" if "test_vector_idx" in str(session.run("SHOW INDEXES").data()) else "✗"))
            logger.info("5. Write Permissions: " + ("✓" if "CartographyTest" in str(session.run("SHOW NODES").data()) else "✗"))
            
            # Detailed recommendations
            logger.info("\nRecommendations:")
            if float(version.split('.')[0]) < 4.4:
                logger.info("• Upgrade to Neo4j 4.4+ or 5.+ for full compatibility")
            if 'enterprise' not in edition.lower() and float(version.split('.')[0]) < 5:
                logger.info("• Consider Enterprise Edition or Neo4j 5.+ for advanced features")
            if not procedures or not procedures['apoc_procedures']:
                logger.info("• Install APOC Core procedures for enhanced functionality")
            if "test_vector_idx" not in str(session.run("SHOW INDEXES").data()):
                logger.info("• Enable vector index support for similarity search")
            
        return True
        
    except Exception as e:
        logger.error(f"\n❌ Compatibility test failed: {str(e)}")
        return False
        
    finally:
        if driver:
            driver.close()
            logger.info("\nTest completed - Neo4j connection closed")

if __name__ == "__main__":
    test_cartography_compatibility()

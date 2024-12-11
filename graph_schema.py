import os
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from neo4j import GraphDatabase
from openai import OpenAI
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GraphSchema:
    """Manages graph database schema and operations with Neo4j."""
    
    def __init__(self):
        """Initialize Neo4j connection and OpenAI client."""
        # Get credentials from environment
        self.uri = os.getenv('NEO4J_URI')
        self.user = os.getenv('NEO4J_USER')
        self.password = os.getenv('NEO4J_PASSWORD')
        openai_api_key = os.getenv('OPENAI_API_KEY')
        
        # Log configuration state
        logger.info("Initializing Graph Schema with configuration:")
        logger.info(f"Neo4j URI configured: {bool(self.uri)}")
        logger.info(f"Neo4j user configured: {bool(self.user)}")
        logger.info(f"Neo4j password configured: {bool(self.password)}")
        logger.info(f"OpenAI API key configured: {bool(openai_api_key)}")
        
        # Detailed URI analysis
        if self.uri:
            uri_parts = self.uri.split('://')
            if len(uri_parts) == 2:
                scheme, rest = uri_parts
                logger.info(f"Neo4j URI scheme: {scheme}")
                # Mask sensitive parts of the URI
                logger.info(f"URI format validation: {'@' in rest}")
            else:
                logger.error("Invalid Neo4j URI format - missing scheme")
        
        # Validate all required credentials
        missing_vars = []
        if not self.uri:
            missing_vars.append("NEO4J_URI")
        if not self.user:
            missing_vars.append("NEO4J_USER")
        if not self.password:
            missing_vars.append("NEO4J_PASSWORD")
        if not openai_api_key:
            missing_vars.append("OPENAI_API_KEY")
            
        if missing_vars:
            error_msg = f"Missing required environment variables: {', '.join(missing_vars)}"
            logger.error(error_msg)
            raise ValueError(error_msg)
            
        # Initialize OpenAI client
        self.openai = OpenAI(api_key=openai_api_key)
        
        logger.info(f"Attempting to connect to Neo4j at {self.uri}")
        
        try:
            from neo4j.exceptions import ServiceUnavailable, AuthError, ConfigurationError
            
            # Initialize Neo4j driver with robust error handling
            try:
                logger.info("Initializing Neo4j driver...")
                
                # Validate and parse URI
                if not self.uri or '://' not in self.uri:
                    raise ConfigurationError("Invalid Neo4j URI format")
                
                # Parse URI components
                uri_scheme, uri_path = self.uri.split('://', 1)
                logger.info(f"Neo4j URI components:")
                logger.info(f"- Full URI: {self.uri}")
                logger.info(f"- Scheme: {uri_scheme}")
                if '@' in uri_path:
                    host = uri_path.split('@')[1]
                else:
                    host = uri_path
                if ':' in host:
                    host = host.split(':')[0]
                logger.info(f"- Host: {host}")
                
                # DNS resolution test
                import socket
                try:
                    logger.info(f"Attempting DNS resolution for {host}...")
                    ip_address = socket.gethostbyname(host)
                    logger.info(f"DNS resolution successful: {host} -> {ip_address}")
                except socket.gaierror as e:
                    logger.error(f"DNS resolution failed for {host}: {str(e)}")
                    raise ConfigurationError(f"Cannot resolve Neo4j host: {host}")
                
                # Initialize driver with Aura-specific configuration
                logger.info("Creating Neo4j driver with Aura configuration...")
                driver_config = {
                    'auth': (self.user, self.password),
                    'connection_timeout': 60,
                    'keep_alive': True,
                    'max_connection_lifetime': 3600,  # 1 hour max connection lifetime for Aura
                    'max_connection_pool_size': 50,   # Aura recommended pool size
                    'connection_acquisition_timeout': 60
                }
                
                logger.info("Configuring Neo4j driver with Aura-specific settings...")
                for key, value in driver_config.items():
                    if key != 'auth':  # Don't log auth details
                        logger.info(f"- {key}: {value}")
                
                self.driver = GraphDatabase.driver(self.uri, **driver_config)
                
                # Detailed connectivity test with diagnostics and Aura-specific retry logic
                retry_count = 0
                max_retries = 5  # Increased for Aura's initial connection delay
                last_error = None
                initial_delay = 2  # seconds
                
                while retry_count < max_retries:
                    try:
                        logger.info(f"Verifying Neo4j connectivity (attempt {retry_count + 1}/{max_retries})")
                        
                        # Step 1: Basic connectivity check
                        logger.info("Step 1: Verifying basic connectivity...")
                        self.driver.verify_connectivity()
                        logger.info("✓ Basic connectivity check passed")
                        
                        # Step 2: Session creation test
                        logger.info("Step 2: Testing session creation...")
                        with self.driver.session() as session:
                            # Step 3: Basic query execution
                            logger.info("Step 3: Testing basic query execution...")
                            test_result = session.run("RETURN 1 as test").single()
                            if not test_result or test_result.get("test") != 1:
                                raise ValueError("Basic query execution failed")
                            logger.info("✓ Basic query execution successful")
                            
                            # Step 4: Version and capability check
                            logger.info("Step 4: Checking Neo4j version and capabilities...")
                            version_info = session.run("CALL dbms.components() YIELD name, versions, edition").single()
                            if version_info:
                                logger.info(f"✓ Connected to Neo4j {version_info['name']} {version_info['edition']}")
                                logger.info(f"✓ Version: {version_info['versions'][0]}")
                            else:
                                logger.warning("! Could not retrieve Neo4j version information")
                            
                            # Step 5: Constraints check
                            logger.info("Step 5: Verifying database permissions...")
                            perm_test = session.run("SHOW CONSTRAINTS").consume()
                            logger.info("✓ Database permissions verified")
                            
                        logger.info("All connection tests passed successfully!")
                        return  # Success - exit the retry loop
                        
                    except AuthError as e:
                        error_msg = f"Neo4j authentication failed: {str(e)}"
                        logger.error(error_msg)
                        raise ValueError(error_msg) from e
                        
                    except ServiceUnavailable as e:
                        retry_count += 1
                        if retry_count == max_retries:
                            error_msg = f"Neo4j Aura service unavailable after {max_retries} attempts: {str(e)}"
                            logger.error(error_msg)
                            logger.error("Please ensure:")
                            logger.error("1. The Aura instance is fully initialized (can take up to 60s)")
                            logger.error("2. The connection URI uses neo4j+s:// scheme")
                            logger.error("3. The instance is in the 'running' state in the Neo4j Aura console")
                            raise ValueError(error_msg) from e
                            
                        wait_time = initial_delay * (2 ** (retry_count - 1))  # Exponential backoff
                        logger.warning(f"Connection attempt {retry_count}/{max_retries} failed.")
                        logger.warning(f"Waiting {wait_time}s for Aura instance initialization...")
                        import time
                        time.sleep(wait_time)
                        
                        # Additional Aura-specific connection diagnostics
                        logger.info(f"Retry {retry_count} diagnostics:")
                        logger.info(f"- Last error: {str(e)}")
                        logger.info(f"- Total wait time: {sum(initial_delay * (2 ** i) for i in range(retry_count))}s")
                        logger.info(f"- Next retry in: {wait_time}s")
                        
                    except ConfigurationError as e:
                        error_msg = f"Neo4j configuration error: {str(e)}"
                        logger.error(error_msg)
                        raise ValueError(error_msg) from e
                        
                    except Exception as e:
                        error_msg = f"Unexpected error during Neo4j connection: {str(e)}"
                        logger.error(error_msg)
                        raise ValueError(error_msg) from e
                        
                if not success:
                    raise ValueError("Failed to establish Neo4j connection after multiple attempts")
                        
            except Exception as e:
                logger.error(f"Failed to connect to Neo4j: {str(e)}")
                logger.error("Please verify your Neo4j URI, username, and password")
                raise
                
        except Exception as e:
            logger.error(f"Failed to initialize Neo4j connection: {str(e)}")
            raise
            
    def init_schema(self):
        """Initialize the graph database schema."""
        try:
            with self.driver.session() as session:
                # Create constraints for User nodes
                session.run("""
                    CREATE CONSTRAINT user_id IF NOT EXISTS
                    FOR (u:User) REQUIRE u.id IS UNIQUE
                """)
                
                # Create constraints for Resource nodes
                session.run("""
                    CREATE CONSTRAINT resource_id IF NOT EXISTS
                    FOR (r:Resource) REQUIRE r.id IS UNIQUE
                """)
                
                logger.info("Successfully initialized Neo4j schema")
                
        except Exception as e:
            logger.error(f"Failed to initialize schema: {str(e)}")
            raise ValueError(f"Schema initialization failed: {str(e)}") from e
            
    def validate_schema(self) -> bool:
        """
        Validate the graph database schema.
        
        Returns:
            bool: True if schema is valid, False otherwise
        """
        try:
            with self.driver.session() as session:
                # Check constraints
                result = session.run("SHOW CONSTRAINTS")
                constraints = [record["name"] for record in result]
                
                required_constraints = ["user_id", "resource_id"]
                missing_constraints = [c for c in required_constraints if c not in constraints]
                
                if missing_constraints:
                    logger.warning(f"Missing constraints: {missing_constraints}")
                    return False
                    
                logger.info("Schema validation successful")
                return True
                
        except Exception as e:
            logger.error(f"Schema validation failed: {str(e)}")
            return False
            
    def create_or_update_user(self, user_data: Dict[str, Any]) -> None:
        """
        Create or update a user node in the graph database.
        
        Args:
            user_data: Dictionary containing user information
            
        Raises:
            ValueError: If required user data is missing
        """
        try:
            required_fields = ['id', 'email']
            if not all(field in user_data for field in required_fields):
                raise ValueError(f"Missing required user fields: {required_fields}")
            
            with self.driver.session() as session:
                # Create or update user node with Cartography-compatible properties
                query = """
                MERGE (u:User {id: $id})
                SET u.email = $email,
                    u.name = $name,
                    u.title = $title,
                    u.department = $department,
                    u.lastupdated = timestamp(),
                    u.platform = 'internal',
                    u.type = 'employee'
                RETURN u
                """
                
                result = session.run(
                    query,
                    id=user_data['id'],
                    email=user_data['email'],
                    name=user_data.get('name', ''),
                    title=user_data.get('title', ''),
                    department=user_data.get('department', '')
                )
                
                user_node = result.single()
                if not user_node:
                    raise ValueError(f"Failed to create/update user with ID: {user_data['id']}")
                    
                logger.info(f"Successfully created/updated user: {user_data['id']}")
                
        except Exception as e:
            logger.error(f"Error creating/updating user: {str(e)}")
            raise ValueError(f"Failed to create/update user: {str(e)}") from e
            
    def __del__(self):
        """Cleanup Neo4j connection."""
        try:
            self.driver.close()
        except Exception as e:
            logger.error(f"Error closing Neo4j connection: {str(e)}")

    def create_node_embedding(self, node_id: str, node_type: str, text_content: str) -> None:
        """Create vector embedding for a node using OpenAI."""
        try:
            # Generate embedding using OpenAI
            response = self.openai.embeddings.create(
                model="text-embedding-3-small",
                input=text_content
            )
            embedding = response.data[0].embedding
            
            # Store embedding in Neo4j
            with self.driver.session() as session:
                query = """
                MATCH (n)
                WHERE n.id = $node_id AND $node_type in labels(n)
                SET n.embedding = $embedding,
                    n.text_content = $text_content,
                    n.last_embedded = timestamp()
                """
                session.run(
                    query,
                    node_id=node_id,
                    node_type=node_type,
                    embedding=embedding,
                    text_content=text_content
                )
                
        except Exception as e:
            logger.error(f"Error creating node embedding: {str(e)}")
            raise

    def get_graph_context(self, query: str, limit: int = 5) -> Dict[str, Any]:
        """Retrieve relevant graph context using vector similarity and relationship traversal."""
        try:
            # Generate query embedding
            response = self.openai.embeddings.create(
                model="text-embedding-3-small",
                input=query
            )
            query_embedding = response.data[0].embedding
            
            # Find similar nodes and their relationships in Neo4j
            with self.driver.session() as session:
                result = session.run("""
                // Find initial similar nodes
                MATCH (n)
                WHERE n.embedding IS NOT NULL
                WITH n, gds.similarity.cosine(n.embedding, $query_embedding) AS similarity
                WHERE similarity > 0.7
                
                // Collect immediate relationships
                OPTIONAL MATCH (n)-[r]->(m)
                WHERE type(r) IN ['TAGGED', 'BELONGS_TO', 'HAS_ACCESS', 'MANAGES', 'OWNS']
                WITH n, similarity, collect(DISTINCT {
                    rel_type: type(r),
                    target_id: m.id,
                    target_name: m.name,
                    target_type: m.type
                }) as outgoing_rels
                
                // Collect reverse relationships
                OPTIONAL MATCH (n)<-[r]-(m)
                WHERE type(r) IN ['TAGGED', 'BELONGS_TO', 'HAS_ACCESS', 'MANAGES', 'OWNS']
                WITH n, similarity, outgoing_rels, collect(DISTINCT {
                    rel_type: type(r),
                    source_id: m.id,
                    source_name: m.name,
                    source_type: m.type
                }) as incoming_rels
                
                // Return enriched node data
                RETURN {
                    id: n.id,
                    labels: labels(n),
                    name: n.name,
                    type: n.type,
                    content: n.text_content,
                    metadata: n.metadata,
                    platform: n.platform,
                    environment: n.environment,
                    location: n.location,
                    owner: n.owner,
                    similarity: similarity,
                    relationships: {
                        outgoing: outgoing_rels,
                        incoming: incoming_rels
                    }
                } as node_data
                ORDER BY similarity DESC
                LIMIT $limit
                """, query_embedding=query_embedding, limit=limit)
                
                nodes = [record["node_data"] for record in result]
                
                return {
                    'nodes': nodes,
                    'query': query
                }
                
        except Exception as e:
            logger.error(f"Error retrieving graph context: {str(e)}")
            raise

    def close(self):
        """Close the Neo4j driver connection."""
        try:
            self.driver.close()
        except Exception as e:
            logger.error(f"Error closing Neo4j connection: {str(e)}")
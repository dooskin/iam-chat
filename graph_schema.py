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
                
                # Analyze URI format
                if not self.uri or '://' not in self.uri:
                    raise ConfigurationError("Invalid Neo4j URI format")
                    
                uri_scheme, uri_path = self.uri.split('://', 1)
                logger.info(f"Neo4j URI analysis:")
                logger.info(f"- Scheme: {uri_scheme}")
                logger.info(f"- Authentication present: {'@' in uri_path}")
                logger.info(f"- Protocol: {'bolt' if 'bolt' in uri_scheme else 'neo4j'}")
                
                # Keep connection config minimal to avoid conflicts with URI settings
                logger.info("Creating Neo4j driver with basic auth...")
                self.driver = GraphDatabase.driver(
                    self.uri,
                    auth=(self.user, self.password)
                )
                
                # Simple connectivity test with detailed diagnostics
                retry_count = 0
                max_retries = 3
                
                while retry_count < max_retries:
                    try:
                        logger.info(f"Verifying Neo4j connectivity (attempt {retry_count + 1}/{max_retries})")
                        
                        # Basic connectivity check
                        self.driver.verify_connectivity()
                        logger.info("Basic connectivity check passed")
                        
                        # Version and capability check
                        with self.driver.session() as session:
                            version_info = session.run("CALL dbms.components() YIELD name, versions, edition").single()
                            if version_info:
                                logger.info(f"Connected to Neo4j {version_info['name']} {version_info['edition']}")
                                logger.info(f"Version: {version_info['versions'][0]}")
                            
                            # Simple query test
                            test_result = session.run("RETURN 1 as test").single()
                            if test_result and test_result["test"] == 1:
                                logger.info("Query execution test passed")
                                return  # Success - exit the retry loop
                            
                        logger.error("Query execution test failed - unexpected result")
                        
                    except AuthError as e:
                        error_msg = f"Neo4j authentication failed: {str(e)}"
                        logger.error(error_msg)
                        raise ValueError(error_msg) from e
                        
                    except ServiceUnavailable as e:
                        retry_count += 1
                        if retry_count == max_retries:
                            error_msg = f"Neo4j service unavailable after {max_retries} attempts: {str(e)}"
                            logger.error(error_msg)
                            raise ValueError(error_msg) from e
                            
                        wait_time = 2 ** retry_count
                        logger.warning(f"Connection attempt {retry_count} failed. Retrying in {wait_time}s...")
                        import time
                        time.sleep(wait_time)
                        
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
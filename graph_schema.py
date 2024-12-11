import os
import logging
from typing import Dict, List, Optional, Any, TypeVar
from datetime import datetime
from neo4j import GraphDatabase
from openai import OpenAI
from contextlib import contextmanager
from dotenv import load_dotenv

# Configure logging first
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
logger.info("Loading environment variables from .env file...")
load_dotenv(override=True)  # Force override existing env vars

# Debug: Print loaded environment variables (without exposing sensitive values)
logger.info("Environment variables loaded:")
logger.info(f"NEO4J_URI configured: {bool(os.getenv('NEO4J_URI'))}")
logger.info(f"NEO4J_USERNAME configured: {bool(os.getenv('NEO4J_USERNAME'))}")
logger.info(f"NEO4J_PASSWORD configured: {bool(os.getenv('NEO4J_PASSWORD'))}")

class GraphSchema:
    """Graph database schema manager with vector embeddings support."""
    
    def __init__(self):
        """Initialize Neo4j connection and OpenAI client."""
        try:
            # Get configuration from environment with explicit defaults from .env
            self.uri = os.getenv('NEO4J_URI')
            self.user = os.getenv('NEO4J_USERNAME')  # Using the exact name from .env file
            self.password = os.getenv('NEO4J_PASSWORD')
            
            # Initialize OpenAI client
            self.openai = OpenAI()
            logger.info("OpenAI client initialized successfully")
            
            # Debug environment variables
            logger.info("Neo4j Connection Configuration:")
            logger.info(f"URI: {self.uri}")
            logger.info(f"Username (NEO4J_USERNAME) present: {bool(self.user)}")
            logger.info(f"Password (NEO4J_PASSWORD) present: {bool(self.password)}")
            
            # Validate Neo4j URI format
            if self.uri:
                uri_parts = self.uri.split('://')
                if len(uri_parts) == 2:
                    protocol, host = uri_parts
                    logger.info(f"URI Protocol: {protocol}")
                    logger.info(f"URI Host: {host}")
                    if not (protocol == 'neo4j+s' and '.databases.neo4j.io' in host):
                        logger.warning("URI format may not be correct for Neo4j Aura")
                else:
                    logger.error("Invalid URI format")
            
            # Validate configuration
            if not all([self.uri, self.user, self.password]):
                raise ValueError("Missing required Neo4j configuration. Please check .env file.")
                
            logger.info("Initializing Graph Schema with configuration:")
            logger.info(f"Neo4j URI: {self.uri}")
            logger.info(f"Neo4j username configured: {bool(self.user)}")
            logger.info(f"Neo4j password configured: {bool(self.password)}")
            
            # Initialize Neo4j driver with Aura-specific configuration
            logger.info("Initializing Neo4j driver with Aura configuration...")
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
                max_connection_lifetime=3600,  # 1 hour max connection lifetime
                max_connection_pool_size=50,   # Recommended pool size for Aura
                connection_timeout=30,         # Reduced timeout for faster failure detection
                connection_acquisition_timeout=60
            )
            
            # Test connection
            logger.info("Testing Neo4j connection...")
            self.driver.verify_connectivity()
            logger.info("Successfully connected to Neo4j")
            
        except Exception as e:
            logger.error(f"Failed to initialize Neo4j connection: {str(e)}")
            logger.error("Please verify your Neo4j URI, username, and password")
            raise

    def init_schema(self):
        """Initialize the graph database schema with Cartography compatibility."""
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
                
                # Create constraints for Group nodes (Cartography compatibility)
                session.run("""
                    CREATE CONSTRAINT group_id IF NOT EXISTS
                    FOR (g:Group) REQUIRE g.id IS UNIQUE
                """)
                
                # Create constraints for Role nodes (Cartography compatibility)
                session.run("""
                    CREATE CONSTRAINT role_id IF NOT EXISTS
                    FOR (r:Role) REQUIRE r.id IS UNIQUE
                """)
                
                # Create constraints for Application nodes (Cartography compatibility)
                session.run("""
                    CREATE CONSTRAINT application_id IF NOT EXISTS
                    FOR (a:Application) REQUIRE a.id IS UNIQUE
                """)
                
                logger.info("Successfully initialized Neo4j schema with Cartography compatibility")
                
        except Exception as e:
            logger.error(f"Failed to initialize schema: {str(e)}")
            raise

    def validate_schema(self) -> bool:
        """
        Validate the graph database schema including Cartography compatibility.
        
        Returns:
            bool: True if schema is valid, False otherwise
        """
        try:
            with self.driver.session() as session:
                # Check constraints
                result = session.run("SHOW CONSTRAINTS")
                constraints = [record["name"] for record in result]
                
                required_constraints = [
                    "user_id", "resource_id", "group_id", 
                    "role_id", "application_id"
                ]
                missing_constraints = [c for c in required_constraints if c not in constraints]
                
                if missing_constraints:
                    logger.warning(f"Missing constraints: {missing_constraints}")
                    return False
                
                # Validate Cartography-specific indices
                try:
                    session.run("""
                        CREATE INDEX user_lastupdated IF NOT EXISTS
                        FOR (u:User) ON (u.lastupdated)
                    """)
                    session.run("""
                        CREATE INDEX resource_lastupdated IF NOT EXISTS
                        FOR (r:Resource) ON (r.lastupdated)
                    """)
                    logger.info("Cartography indices validated")
                except Exception as e:
                    logger.warning(f"Could not create Cartography indices: {str(e)}")
                    # Don't fail validation for index creation
                
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
        """
        try:
            required_fields = ['id', 'email']
            if not all(field in user_data for field in required_fields):
                raise ValueError(f"Missing required user fields: {required_fields}")
            
            with self.driver.session() as session:
                query = """
                MERGE (u:User {id: $id})
                SET u.email = $email,
                    u.name = $name,
                    u.title = $title,
                    u.department = $department,
                    u.lastupdated = timestamp()
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
            if hasattr(self, 'driver'):
                self.driver.close()
        except Exception as e:
            logger.error(f"Error closing Neo4j connection: {str(e)}")
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
            self.user = os.getenv('NEO4J_USER')  # Using the exact name from .env file
            self.password = os.getenv('NEO4J_PASSWORD')
            
            # Validate configuration
            if not all([self.uri, self.user, self.password]):
                missing = []
                if not self.uri: missing.append('NEO4J_URI')
                if not self.user: missing.append('NEO4J_USER')
                if not self.password: missing.append('NEO4J_PASSWORD')
                raise ValueError(f"Missing required Neo4j configuration: {', '.join(missing)}")
            
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
                # Create constraints for core nodes
                constraints = [
                    ("User", "user_id"),
                    ("Resource", "resource_id"),
                    ("Group", "group_id"),
                    ("Role", "role_id"),
                    ("Application", "application_id"),
                    ("AWSAccount", "aws_account_id"),
                    ("GCPProject", "gcp_project_id"),
                    ("AzureSubscription", "azure_subscription_id"),
                    ("Device", "device_id"),
                    ("Network", "network_id")
                ]
                
                # Create constraints with error handling
                for node_type, constraint_name in constraints:
                    try:
                        session.run(f"""
                            CREATE CONSTRAINT {constraint_name} IF NOT EXISTS
                            FOR (n:{node_type}) REQUIRE n.id IS UNIQUE
                        """)
                        logger.info(f"Created/verified constraint: {constraint_name}")
                    except Exception as e:
                        logger.warning(f"Error creating constraint {constraint_name}: {str(e)}")
                
                # Create vector search indices
                core_types = ['User', 'Resource', 'Group', 'Role', 'Application']
                
                # Vector embedding indices
                for node_type in core_types:
                    try:
                        session.run(f"""
                            CREATE INDEX {node_type.lower()}_vector_idx IF NOT EXISTS
                            FOR (n:{node_type})
                            ON (n.embedding)
                        """)
                        logger.info(f"Created/verified vector index for {node_type}")
                    except Exception as e:
                        logger.warning(f"Error creating vector index for {node_type}: {str(e)}")
                
                # Cartography sync timestamp indices
                for node_type in core_types:
                    try:
                        session.run(f"""
                            CREATE INDEX {node_type.lower()}_sync_idx IF NOT EXISTS
                            FOR (n:{node_type})
                            ON (n.lastupdated)
                        """)
                        logger.info(f"Created/verified sync index for {node_type}")
                    except Exception as e:
                        logger.warning(f"Error creating sync index for {node_type}: {str(e)}")
                
                # Create relationship indices for each type separately
                try:
                    for rel_type in ["HAS_PERMISSION", "BELONGS_TO", "MANAGES", "OWNS", "ACCESSES"]:
                        session.run(f"""
                            CREATE INDEX {rel_type.lower()}_idx IF NOT EXISTS
                            FOR ()-[r:{rel_type}]-()
                            ON type(r)
                        """)
                        logger.info(f"Created/verified relationship index for {rel_type}")
                except Exception as e:
                    logger.warning(f"Error creating relationship indices: {str(e)}")
                
                # Verify schema initialization
                result = session.run("SHOW CONSTRAINTS")
                constraints = [record["name"] for record in result]
                logger.info(f"Active constraints: {', '.join(constraints)}")
                
                logger.info("Successfully initialized Neo4j schema with Cartography compatibility")
                return True
                
        except Exception as e:
            logger.error(f"Failed to initialize schema: {str(e)}")
            raise
                
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

    def create_node_embedding(self, node_id: str, node_type: str, text_content: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Create vector embedding for a node using OpenAI with enhanced metadata support.
        
        Args:
            node_id: Unique identifier for the node
            node_type: Type/label of the node
            text_content: Text to generate embedding from
            metadata: Optional metadata to store with the node
        """
        try:
            # Generate embedding using OpenAI
            response = self.openai.embeddings.create(
                model="text-embedding-3-small",
                input=text_content
            )
            embedding = response.data[0].embedding
            
            # Prepare metadata with defaults
            node_metadata = {
                'last_updated': datetime.now().isoformat(),
                'content_length': len(text_content),
                'embedding_model': 'text-embedding-3-small'
            }
            if metadata:
                node_metadata.update(metadata)
            
            # Store embedding with metadata in Neo4j
            with self.driver.session() as session:
                query = """
                MATCH (n)
                WHERE n.id = $node_id AND $node_type in labels(n)
                SET n.embedding = $embedding,
                    n.text_content = $text_content,
                    n.metadata = $metadata,
                    n.last_embedded = timestamp(),
                    n.lastupdated = timestamp()  // Cartography compatibility
                """
                session.run(
                    query,
                    node_id=node_id,
                    node_type=node_type,
                    embedding=embedding,
                    text_content=text_content,
                    metadata=node_metadata
                )
                
            logger.info(f"Successfully created embedding for node {node_id} of type {node_type}")
                
        except Exception as e:
            logger.error(f"Error creating node embedding: {str(e)}")
            raise

    def get_graph_context(self, query: str, limit: int = 5, min_similarity: float = 0.7, max_hops: int = 2) -> Dict[str, Any]:
        """
        Retrieve relevant graph context using vector similarity and advanced relationship traversal.
        
        Args:
            query: Search query text
            limit: Maximum number of primary nodes to return
            min_similarity: Minimum cosine similarity threshold
            max_hops: Maximum number of relationship hops to traverse
            
        Returns:
            Dict containing primary nodes, related nodes, and query metadata
        """
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
                // Find initial similar nodes using vector similarity
                MATCH (n)
                WHERE n.embedding IS NOT NULL
                WITH n, gds.similarity.cosine(n.embedding, $query_embedding) AS similarity
                WHERE similarity > $min_similarity
                
                // Traverse relationships up to max_hops
                CALL apoc.path.subgraphAll(n, {
                    relationshipFilter: 'HAS_PERMISSION|BELONGS_TO|MANAGES|OWNS|ACCESSES',
                    maxLevel: $max_hops
                })
                YIELD nodes, relationships
                
                // Process nodes
                UNWIND nodes as related_node
                WITH n, similarity, related_node, relationships
                
                // Collect node metadata
                WITH n, similarity, related_node, relationships,
                CASE WHEN related_node = n THEN 0 ELSE 
                    REDUCE(distance = -1, rel IN relationships |
                        CASE WHEN rel.source = n.id OR rel.target = n.id
                        THEN 1 ELSE distance + 1 END)
                END as hop_distance
                
                // Group and return enriched data
                WITH n, similarity,
                collect(DISTINCT {
                    node: related_node,
                    hop_distance: hop_distance,
                    labels: labels(related_node),
                    properties: properties(related_node)
                }) as context_nodes,
                collect(DISTINCT {
                    source: startNode(rel).id,
                    target: endNode(rel).id,
                    type: type(rel),
                    properties: properties(rel)
                }) as context_relationships
                
                // Return complete context
                RETURN {
                    primary_node: {
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
                        last_updated: n.lastupdated  // Cartography compatibility
                    },
                    context: {
                        nodes: context_nodes,
                        relationships: context_relationships
                    }
                } as graph_context
                ORDER BY similarity DESC
                LIMIT $limit
                """, 
                query_embedding=query_embedding,
                limit=limit,
                min_similarity=min_similarity,
                max_hops=max_hops
                )
                
                contexts = [record["graph_context"] for record in result]
                
                # Process and structure the response
                return {
                    'query': query,
                    'query_time': datetime.now().isoformat(),
                    'primary_nodes': [ctx['primary_node'] for ctx in contexts],
                    'context_graph': {
                        'nodes': list({node['node']['id']: node 
                                    for ctx in contexts 
                                    for node in ctx['context']['nodes']}.values()),
                        'relationships': list({(rel['source'], rel['target'], rel['type']): rel 
                                            for ctx in contexts 
                                            for rel in ctx['context']['relationships']}.values())
                    },
                    'metadata': {
                        'total_contexts': len(contexts),
                        'max_similarity': max([ctx['primary_node']['similarity'] for ctx in contexts]) if contexts else 0,
                        'min_similarity': min([ctx['primary_node']['similarity'] for ctx in contexts]) if contexts else 0
                    }
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
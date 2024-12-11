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
                        # Create standard relationship property indices
                        session.run(f"""
                            CREATE INDEX {rel_type.lower()}_timestamp_idx IF NOT EXISTS
                            FOR ()-[r:{rel_type}]-()
                            ON (r.timestamp)
                        """)
                        session.run(f"""
                            CREATE INDEX {rel_type.lower()}_type_idx IF NOT EXISTS
                            FOR ()-[r:{rel_type}]-()
                            ON (r.type)
                        """)
                        logger.info(f"Created/verified relationship indices for {rel_type}")
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
                
                logger.info("Schema validation successful")
                return True
                
        except Exception as e:
            logger.error(f"Schema validation failed: {str(e)}")
            return False

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
            
            # Store embedding with flattened metadata in Neo4j
            with self.driver.session() as session:
                query = """
                MATCH (n)
                WHERE n.id = $node_id AND $node_type in labels(n)
                SET n.embedding = $embedding,
                    n.text_content = $text_content,
                    n.embedding_model = $embedding_model,
                    n.last_updated = $last_updated,
                    n.content_length = $content_length,
                    n.last_embedded = timestamp(),
                    n.lastupdated = timestamp()  // Cartography compatibility
                """
                if metadata:
                    for key, value in metadata.items():
                        query += f",\n    n.{key} = ${key}"
                
                params = {
                    'node_id': node_id,
                    'node_type': node_type,
                    'embedding': embedding,
                    'text_content': text_content,
                    'embedding_model': node_metadata['embedding_model'],
                    'last_updated': node_metadata['last_updated'],
                    'content_length': node_metadata['content_length']
                }
                if metadata:
                    params.update(metadata)
                    
                session.run(query, params)
                
            logger.info(f"Successfully created embedding for node {node_id} of type {node_type}")
                
        except Exception as e:
            logger.error(f"Error creating node embedding: {str(e)}")
            raise

    def get_graph_context(self, query: str, limit: int = 5, max_hops: int = 2, page_size: int = 100, score_threshold: float = 0.6) -> Dict[str, Any]:
        """
        Retrieve relevant graph context using similarity search and relationship traversal.
        
        Args:
            query: Search query text
            limit: Maximum number of primary nodes to return
            max_hops: Maximum number of relationship hops to traverse
            page_size: Number of results to process per page
            score_threshold: Minimum similarity score for vector search results
        """
        try:
            # Initialize response metadata
            metadata = {
                'query_time': datetime.now().isoformat(),
                'max_similarity': 0.0,
                'total_contexts': 0,
                'total_related_nodes': 0,
                'total_relationships': 0
            }
            
            # Initialize vector store for similarity search
            from vector_store import VectorStore
            vector_store = VectorStore()
            similar_nodes = vector_store.batch_search_similar(
                query=query,
                limit_per_type=limit,
                score_threshold=score_threshold
            )
            
            # Collect all node IDs and track max similarity
            node_ids = []
            for collection_results in similar_nodes.values():
                for result in collection_results:
                    node_ids.append(result["node_id"])
                    if "similarity" in result:
                        metadata['max_similarity'] = max(metadata['max_similarity'], result["similarity"])
            
            if not node_ids:
                logger.warning("No similar nodes found in vector store")
                return {
                    'query': query,
                    'query_time': metadata['query_time'],
                    'primary_nodes': [],
                    'context_graph': {'nodes': [], 'relationships': []},
                    'metadata': metadata
                }
            
            # Find connected nodes and relationships in Neo4j
            with self.driver.session() as session:
                # Convert max_hops to integer for Cypher query
                hops = int(max_hops)
                result = session.run("""
                // Match starting nodes
                MATCH (n)
                WHERE n.id IN $node_ids
                
                // Use updated subquery syntax
                CALL {
                    WITH n
                    MATCH p=(n)-[r*1..2]-(related)
                    WHERE ALL(rel IN r WHERE type(rel) IN ['HAS_PERMISSION', 'BELONGS_TO', 'MANAGES', 'OWNS', 'ACCESSES'])
                    RETURN p as path, related
                    SKIP $skip
                    LIMIT $page_size
                }
                
                // Collect and structure data
                WITH n,
                     collect({
                         path: path,
                         related: related,
                         nodes: nodes(path),
                         relationships: relationships(path)
                     }) as context_paths
                
                // Return structured result
                RETURN {
                    primary_node: {
                        id: n.id,
                        labels: labels(n),
                        properties: properties(n)
                    },
                    context: context_paths
                } as result
                """,
                node_ids=node_ids,
                skip=0,
                page_size=page_size
                )
                
                # Process query results
                contexts = []
                nodes = set()
                relationships = []
                
                for record in result:
                    ctx = record["result"]
                    primary_node = ctx["primary_node"]
                    
                    # Initialize similarity score
                    primary_node["similarity"] = 0.0
                    
                    # Update similarity and metadata from vector store results
                    for collection_results in similar_nodes.values():
                        for result in collection_results:
                            if result["node_id"] == primary_node["id"]:
                                primary_node["similarity"] = result.get("similarity", 0.0)
                                if "metadata" in result:
                                    primary_node.update(result["metadata"])
                    
                    # Add timestamp
                    primary_node["retrieved_at"] = datetime.now().isoformat()
                    contexts.append(primary_node)
                    
                    # Process context paths
                    for path_data in ctx["context"]:
                        # Add all nodes from the path
                        for node in path_data["nodes"]:
                            # Convert Neo4j Node to dictionary
                            node_dict = {
                                'id': node['id'] if 'id' in node else None,
                                'labels': list(node.labels) if hasattr(node, 'labels') else [],
                                'properties': dict(node)
                            }
                            nodes.add(frozenset(node_dict.items()))
                        
                        # Process relationships
                        for rel in path_data["relationships"]:
                            rel_data = {
                                "type": rel.type if hasattr(rel, 'type') else str(type(rel)),
                                "properties": dict(rel),
                                "start_node": rel.start_node['id'] if hasattr(rel, 'start_node') else None,
                                "end_node": rel.end_node['id'] if hasattr(rel, 'end_node') else None
                            }
                            relationships.append(rel_data)
                
                # Update metadata
                metadata.update({
                    'total_contexts': len(contexts),
                    'total_related_nodes': len(nodes),
                    'total_relationships': len(relationships)
                })
                
                # Structure final response
                return {
                    'query': query,
                    'query_time': metadata['query_time'],
                    'primary_nodes': contexts,
                    'context_graph': {
                        'nodes': [dict(node) for node in nodes],
                        'relationships': relationships
                    },
                    'metadata': metadata
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
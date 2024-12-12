import os
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from neo4j import GraphDatabase
from openai import OpenAI

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GraphDB:
    """Graph database manager with vector embeddings support for RAG."""
    
    def __init__(self):
        """Initialize Neo4j connection and OpenAI client."""
        try:
            # Get configuration from environment
            self.uri = os.getenv('NEO4J_URI')
            self.user = os.getenv('NEO4J_USER')
            self.password = os.getenv('NEO4J_PASSWORD')
            
            if not all([self.uri, self.user, self.password]):
                raise ValueError("NEO4J_URI, NEO4J_USER, and NEO4J_PASSWORD environment variables are required")
            
            logger.info("Initializing Neo4j connection...")
            
            # Initialize Neo4j driver with connection pooling
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
                max_connection_lifetime=3600,  # 1 hour
                max_connection_pool_size=50,
                connection_acquisition_timeout=60
            )
            
            # Initialize OpenAI client
            self.openai = OpenAI()
            logger.info("OpenAI client initialized")
            
            # Test connection and verify Neo4j version
            self._test_connection()
            self._verify_neo4j_version()
            logger.info("Successfully connected to Neo4j")
            
        except Exception as e:
            logger.error(f"Failed to initialize Neo4j connection: {str(e)}")
            raise
            
    def _verify_neo4j_version(self):
        """Verify Neo4j version supports vector operations."""
        with self.driver.session() as session:
            result = session.run("CALL dbms.components() YIELD versions")
            version = result.single()["versions"][0]
            logger.info(f"Neo4j version: {version}")
            
            # Parse version string, handling both standard and Aura formats
            version_clean = version.split('-')[0]  # Remove Aura suffix if present
            version_parts = version_clean.split('.')
            
            try:
                major = int(version_parts[0])
                # For versions like "5.26-aura", we only need the major version
                if major < 5:
                    raise RuntimeError(f"Neo4j version {version} does not support vector operations. Version 5.0 or higher is required.")
                logger.info(f"✓ Neo4j version {version} supports vector operations")
            except (IndexError, ValueError) as e:
                raise RuntimeError(f"Unable to parse Neo4j version '{version}': {str(e)}")
            
    def _test_connection(self):
        """Test the Neo4j connection."""
        with self.driver.session() as session:
            result = session.run("RETURN 1 AS num")
            assert result.single()["num"] == 1
            
    def init_schema(self) -> bool:
        """Initialize the graph database schema with constraints and vector indices."""
        try:
            logger.info("\n=== Initializing Neo4j Schema ===")
            with self.driver.session() as session:
                # First verify if Neo4j supports vector operations
                logger.info("Verifying Neo4j capabilities...")
                try:
                    result = session.run("CALL dbms.procedures() YIELD name WHERE name CONTAINS 'vector'")
                    vector_procedures = [record["name"] for record in result]
                    if not vector_procedures:
                        raise RuntimeError("Neo4j vector procedures not available. Please ensure Neo4j 5.11+ is installed with vector index support.")
                    logger.info(f"Found vector procedures: {', '.join(vector_procedures)}")
                except Exception as e:
                    logger.error("Failed to verify Neo4j vector capabilities:")
                    logger.error(str(e))
                    raise
                
                logger.info("\nCreating schema constraints and indices...")
                
                # Drop existing vector index if it exists
                try:
                    session.run("""
                        CALL db.index.vector.drop('embedding_idx')
                        YIELD name
                        RETURN name
                    """)
                    logger.info("Dropped existing vector index")
                except Exception:
                    logger.info("No existing vector index to drop")
                
                # Create constraints for core vertex types
                constraints = [
                    "CREATE CONSTRAINT user_id IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE",
                    "CREATE CONSTRAINT resource_id IF NOT EXISTS FOR (r:Resource) REQUIRE r.id IS UNIQUE",
                    "CREATE CONSTRAINT group_id IF NOT EXISTS FOR (g:Group) REQUIRE g.id IS UNIQUE",
                    "CREATE CONSTRAINT role_id IF NOT EXISTS FOR (r:Role) REQUIRE r.id IS UNIQUE",
                    "CREATE CONSTRAINT app_id IF NOT EXISTS FOR (a:Application) REQUIRE a.id IS UNIQUE"
                ]
                
                # Create property indices
                indices = [
                    "CREATE INDEX user_email IF NOT EXISTS FOR (n:User) ON (n.email)",
                    "CREATE INDEX resource_name IF NOT EXISTS FOR (n:Resource) ON (n.name)",
                ]
                
                # Create constraints
                for constraint in constraints:
                    try:
                        session.run(constraint)
                        logger.info(f"Created constraint: {constraint}")
                    except Exception as e:
                        logger.warning(f"Error creating constraint: {str(e)}")
                
                # Create indices
                for index in indices:
                    try:
                        session.run(index)
                        logger.info(f"Created index: {index}")
                    except Exception as e:
                        logger.warning(f"Error creating index: {str(e)}")
                
                # Create vector index
                try:
                    session.run("""
                    CALL db.index.vector.createNodeIndex(
                        'embedding_idx',
                        ['User', 'Resource', 'Group', 'Role', 'Application'],
                        ['embedding'],
                        1536,
                        'cosine'
                    )
                    """)
                    logger.info("Created vector index for embeddings")
                except Exception as e:
                    logger.error(f"Error creating vector index: {str(e)}")
                    raise
                
                logger.info("Successfully initialized Neo4j schema")
                return True
                
        except Exception as e:
            logger.error(f"Failed to initialize schema: {str(e)}")
            raise
            
    def create_node_embedding(self, node_id: str, node_type: str, text_content: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Create a node with vector embedding using OpenAI."""
        try:
            logger.info(f"Generating embedding for node {node_id}")
            
            # Validate inputs
            if not text_content.strip():
                raise ValueError("Text content cannot be empty")
            
            if not node_type in ['User', 'Resource', 'Group', 'Role', 'Application']:
                raise ValueError(f"Invalid node type: {node_type}. Must be one of: User, Resource, Group, Role, Application")
            
            # Generate embedding using OpenAI with retries
            max_retries = 3
            retry_count = 0
            last_error = None
            
            while retry_count < max_retries:
                try:
                    response = self.openai.embeddings.create(
                        model="text-embedding-3-small",
                        input=text_content,
                        encoding_format="float"
                    )
                    embedding = response.data[0].embedding
                    break
                except Exception as e:
                    retry_count += 1
                    last_error = str(e)
                    if retry_count < max_retries:
                        wait_time = min(2 ** retry_count, 30)
                        logger.warning(f"OpenAI API error (attempt {retry_count}/{max_retries}): {last_error}")
                        logger.info(f"Retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                    else:
                        raise Exception(f"Failed to generate embedding after {max_retries} attempts: {last_error}")
            
            # Validate embedding
            if len(embedding) != 1536:
                raise ValueError(f"Invalid embedding dimension: {len(embedding)}. Expected 1536")
            
            # Prepare node properties
            timestamp = int(datetime.now().timestamp() * 1000)
            properties = {
                'id': node_id,
                'text_content': text_content,
                'embedding': embedding,
                'vector_dim': 1536,  # Fixed dimension for text-embedding-3-small
                'last_updated': datetime.now().isoformat(),
                'content_length': len(text_content),
                'embedding_model': 'text-embedding-3-small',
                'lastupdated': timestamp,
                'firstseen': timestamp
            }
            
            # Add any additional metadata
            if metadata:
                # Validate metadata values
                for key, value in metadata.items():
                    if not isinstance(value, (str, int, float, bool)):
                        raise ValueError(f"Invalid metadata value type for {key}: {type(value)}. Must be primitive type")
                properties.update(metadata)
            
            # Create node with embedding
            query = f"""
            MERGE (n:{node_type} {{id: $id}})
            SET n += $properties
            WITH n
            CALL db.index.vector.updateNode('embedding_idx', n)
            YIELD node
            RETURN n
            """
            
            with self.driver.session() as session:
                try:
                    result = session.run(
                        query,
                        id=node_id,
                        properties=properties
                    )
                    node = result.single()
                    
                    if not node:
                        raise Exception(f"Failed to create node {node_id}")
                        
                    logger.info(f"Successfully created node {node_id} with embedding")
                    logger.info(f"Node properties: id={node_id}, type={node_type}, content_length={len(text_content)}")
                    
                except Exception as e:
                    logger.error(f"Neo4j error creating node {node_id}: {str(e)}")
                    logger.error("Query:", query)
                    logger.error("Node ID:", node_id)
                    logger.error("Node Type:", node_type)
                    raise
                
        except Exception as e:
            logger.error(f"Error creating node embedding: {str(e)}")
            raise
            
    def get_similar_nodes(self, query_text: str, limit: int = 5, score_threshold: float = 0.6, node_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Find similar nodes using vector similarity search."""
        try:
            logger.info(f"Performing similarity search for: {query_text[:100]}...")
            
            # Validate inputs
            if not query_text.strip():
                raise ValueError("Query text cannot be empty")
            
            if limit < 1:
                raise ValueError("Limit must be positive")
            
            if not 0 <= score_threshold <= 1:
                raise ValueError("Score threshold must be between 0 and 1")
            
            # Generate query embedding with retries
            max_retries = 3
            retry_count = 0
            last_error = None
            
            while retry_count < max_retries:
                try:
                    response = self.openai.embeddings.create(
                        model="text-embedding-3-small",
                        input=query_text,
                        encoding_format="float"
                    )
                    query_embedding = response.data[0].embedding
                    break
                except Exception as e:
                    retry_count += 1
                    last_error = str(e)
                    if retry_count < max_retries:
                        wait_time = min(2 ** retry_count, 30)
                        logger.warning(f"OpenAI API error (attempt {retry_count}/{max_retries}): {last_error}")
                        logger.info(f"Retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                    else:
                        raise Exception(f"Failed to generate query embedding after {max_retries} attempts: {last_error}")
            
            # Validate embedding
            if len(query_embedding) != 1536:
                raise ValueError(f"Invalid embedding dimension: {len(query_embedding)}. Expected 1536")
            
            # Build type filter if specified
            type_filter = ""
            if node_types:
                valid_types = ['User', 'Resource', 'Group', 'Role', 'Application']
                invalid_types = [t for t in node_types if t not in valid_types]
                if invalid_types:
                    raise ValueError(f"Invalid node types: {invalid_types}. Must be one of: {valid_types}")
                type_filter = f"WHERE labels(node)[0] IN {node_types}"
            
            # Vector similarity search query with optional type filtering
            query = f"""
            CALL db.index.vector.queryNodes(
                'embedding_idx',
                $embedding,
                $k
            ) YIELD node, score
            {type_filter}
            WITH node, score
            WHERE score >= $threshold
            RETURN 
                node.id as id,
                labels(node)[0] as label,
                node.text_content as content,
                {
                    name: node.name,
                    email: node.email,
                    department: node.department,
                    created_at: node.created_at,
                    last_updated: node.last_updated
                } as properties,
                score
            ORDER BY score DESC
            """
            
            with self.driver.session() as session:
                try:
                    result = session.run(
                        query,
                        k=limit,
                        embedding=query_embedding,
                        threshold=score_threshold
                    )
                    
                    similar_nodes = [dict(record) for record in result]
                    logger.info(f"Found {len(similar_nodes)} similar nodes")
                    
                    if similar_nodes:
                        logger.info("Top match:")
                        top = similar_nodes[0]
                        logger.info(f"• ID: {top['id']}")
                        logger.info(f"• Type: {top['label']}")
                        logger.info(f"• Score: {top['score']:.3f}")
                        logger.info(f"• Content: {top['content'][:100]}...")
                    
                    return similar_nodes
                    
                except Exception as e:
                    logger.error(f"Neo4j error in similarity search: {str(e)}")
                    logger.error("Query:", query)
                    logger.error("Parameters:", {
                        'limit': limit,
                        'threshold': score_threshold,
                        'node_types': node_types
                    })
                    raise
                
        except Exception as e:
            logger.error(f"Error in similarity search: {str(e)}")
            raise
            
    def close(self):
        """Close the Neo4j connection."""
        if self.driver:
            self.driver.close()

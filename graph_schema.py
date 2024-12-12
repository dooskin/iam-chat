import os
import json
import logging
from typing import Dict, Any, List, Optional
from neo4j import GraphDatabase
from openai import OpenAI

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GraphSchema:
    """Manages Neo4j graph schema with Cartography compatibility and vector search capabilities."""
    
    def __init__(self):
        """Initialize Neo4j connection and OpenAI client."""
        # Initialize OpenAI client
        openai_api_key = os.environ.get('OPENAI_API_KEY')
        if not openai_api_key:
            raise ValueError("Missing OpenAI API key")
        self.openai = OpenAI(api_key=openai_api_key)
        
        # Set Neo4j connection parameters with defaults for local development
        self.uri = os.environ.get('NEO4J_URI', 'bolt://localhost:7688')
        self.user = os.environ.get('NEO4J_USER', 'neo4j')
        self.password = os.environ.get('NEO4J_PASSWORD', 'accessbot')
        
        # Log Neo4j connection parameters (without sensitive data)
        logger.info(f"Initializing Neo4j connection with URI: {self.uri}")
        logger.info(f"Neo4j user configured: {bool(self.user)}")
        logger.info(f"Neo4j password configured: {bool(self.password)}")
            
        # Initialize driver with proper error handling
        try:
            from neo4j.exceptions import ServiceUnavailable, AuthError
            
            # Set default local connection if not provided
            if not self.uri:
                self.uri = "bolt://localhost:7688"  # Using custom port from docker-compose
            if not self.user:
                self.user = "neo4j"
            if not self.password:
                self.password = "accessbot"  # Default password from docker-compose
            
            logger.info(f"Attempting to connect to Neo4j at {self.uri}")
            
            # Initialize Neo4j driver with local development configuration
            logger.info("Creating Neo4j driver with configured parameters...")
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
                max_connection_lifetime=3600,  # 1 hour
                max_connection_pool_size=50,
                connection_acquisition_timeout=60,
                connection_timeout=30
            )
            
            # Test connection with retry logic
            retry_count = 0
            max_retries = 3
            while retry_count < max_retries:
                try:
                    logger.info(f"Attempting to verify Neo4j connectivity (attempt {retry_count + 1}/{max_retries})")
                    self.driver.verify_connectivity()
                    logger.info("Successfully connected to Neo4j database")
                    break
                except AuthError as e:
                    logger.error(f"Authentication failed: {str(e)}")
                    raise ValueError("Neo4j authentication failed - please check credentials") from e
                except ServiceUnavailable as e:
                    retry_count += 1
                    if retry_count == max_retries:
                        logger.error(f"Failed to connect after {max_retries} attempts")
                        raise ValueError(f"Unable to establish Neo4j connection: {str(e)}") from e
                    logger.warning(f"Connection attempt {retry_count} failed: {str(e)}. Retrying in {2 ** retry_count} seconds...")
                    import time
                    time.sleep(2 ** retry_count)  # Exponential backoff
                except Exception as e:
                    logger.error(f"Unexpected error during Neo4j connection: {str(e)}")
                    raise ValueError(f"Unexpected error connecting to Neo4j: {str(e)}") from e
                    
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {str(e)}")
            logger.error("Please verify your Neo4j URI, username, and password")
            raise

    def init_schema(self):
        """Initialize Neo4j schema with enhanced constraints and indexes for Cartography compatibility."""
        try:
            with self.driver.session() as session:
                # Base Cartography node constraints using Neo4j 5.x syntax
                constraints = [
                    # Core asset management
                    "CREATE CONSTRAINT IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE",
                    
                    # Identity and access management
                    "CREATE CONSTRAINT IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE",
                    "CREATE CONSTRAINT IF NOT EXISTS FOR (g:Group) REQUIRE g.id IS UNIQUE",
                    "CREATE CONSTRAINT IF NOT EXISTS FOR (r:Role) REQUIRE r.id IS UNIQUE",
                    
                    # Cloud resources
                    "CREATE CONSTRAINT IF NOT EXISTS FOR (p:GCPProject) REQUIRE p.id IS UNIQUE",
                    "CREATE CONSTRAINT IF NOT EXISTS FOR (sa:ServiceAccount) REQUIRE sa.id IS UNIQUE",
                    "CREATE CONSTRAINT IF NOT EXISTS FOR (r:Resource) REQUIRE r.id IS UNIQUE",
                    
                    # HR system integration
                    "CREATE CONSTRAINT IF NOT EXISTS FOR (e:Employee) REQUIRE e.id IS UNIQUE",
                    "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Department) REQUIRE d.id IS UNIQUE",
                    
                    # SaaS integration
                    "CREATE CONSTRAINT IF NOT EXISTS FOR (c:Contact) REQUIRE c.id IS UNIQUE",
                    "CREATE CONSTRAINT IF NOT EXISTS FOR (w:WorkdayEmployee) REQUIRE w.id IS UNIQUE"
                ]
                
                for constraint in constraints:
                    try:
                        session.run(constraint)
                    except Exception as e:
                        logger.error(f"Error creating constraint: {str(e)}")
                        continue
                
                # Enhanced indexes for RAG and Cartography integration
                indexes = [
                    # Text-based search indexes
                    "CREATE FULLTEXT INDEX asset_name_search IF NOT EXISTS FOR (a:Asset) ON EACH [a.name]",
                    "CREATE FULLTEXT INDEX resource_name_search IF NOT EXISTS FOR (r:Resource) ON EACH [r.name]",
                    "CREATE FULLTEXT INDEX user_email_search IF NOT EXISTS FOR (u:User) ON EACH [u.email]",
                    
                    # Property indexes for common queries
                    "CREATE INDEX asset_type_lookup IF NOT EXISTS FOR (a:Asset) ON (a.type)",
                    "CREATE INDEX asset_platform_lookup IF NOT EXISTS FOR (a:Asset) ON (a.platform)",
                    "CREATE INDEX asset_env_lookup IF NOT EXISTS FOR (a:Asset) ON (a.environment)",
                    "CREATE INDEX asset_updated_lookup IF NOT EXISTS FOR (a:Asset) ON (a.lastupdated)",
                    
                    # Vector embedding index
                    "CREATE INDEX embedding_lookup IF NOT EXISTS FOR (n:Asset) ON (n.embedding)"
                ]
                
                for index in indexes:
                    try:
                        session.run(index)
                    except Exception as e:
                        logger.error(f"Error creating index: {str(e)}")
                        continue
                
            logger.info("Successfully initialized Neo4j schema")
            
        except Exception as e:
            logger.error(f"Error initializing schema: {str(e)}")
            raise

    def validate_schema(self) -> bool:
        """Validate Neo4j schema setup and verify indexes and constraints."""
        try:
            with self.driver.session() as session:
                # Check constraints
                result = session.run("""
                SHOW CONSTRAINTS
                YIELD name, labelsOrTypes, properties
                RETURN collect({
                    name: name,
                    labels: labelsOrTypes,
                    properties: properties
                }) as constraints
                """)
                constraints = result.single()["constraints"]
                
                # Check indexes
                result = session.run("""
                SHOW INDEXES
                YIELD name, labelsOrTypes, properties, type
                RETURN collect({
                    name: name,
                    labels: labelsOrTypes,
                    properties: properties,
                    type: type
                }) as indexes
                """)
                indexes = result.single()["indexes"]
                
                # Validate required components
                required_labels = {'Asset', 'User', 'Role', 'Group', 'ServiceAccount', 'GCPProject'}
                required_indexes = {'asset_type_idx', 'embedding_idx', 'vector_similarity_idx'}
                
                existing_labels = set()
                existing_indexes = set()
                
                for constraint in constraints:
                    existing_labels.update(constraint['labels'])
                
                for index in indexes:
                    existing_indexes.add(index['name'])
                
                missing_labels = required_labels - existing_labels
                missing_indexes = required_indexes - existing_indexes
                
                if missing_labels or missing_indexes:
                    if missing_labels:
                        logger.error(f"Missing required labels: {missing_labels}")
                    if missing_indexes:
                        logger.error(f"Missing required indexes: {missing_indexes}")
                    return False
                
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
            metadata: Optional dictionary of metadata to store with the embedding
        """
        try:
            # Prepare enriched text content with metadata
            enriched_content = text_content
            if metadata:
                metadata_text = " ".join([f"{k}: {v}" for k, v in metadata.items() if v])
                enriched_content = f"{text_content}\nMetadata: {metadata_text}"
            
            # Generate embedding using OpenAI
            response = self.openai.embeddings.create(
                model="text-embedding-3-small",
                input=enriched_content
            )
            embedding = response.data[0].embedding
            
            # Store embedding and metadata in Neo4j
            with self.driver.session() as session:
                query = """
                MATCH (n)
                WHERE n.id = $node_id AND $node_type in labels(n)
                SET n.embedding = $embedding,
                    n.text_content = $text_content,
                    n.enriched_content = $enriched_content,
                    n.embedding_metadata = $metadata,
                    n.last_embedded = timestamp()
                """
                session.run(
                    query,
                    node_id=node_id,
                    node_type=node_type,
                    embedding=embedding,
                    text_content=text_content,
                    enriched_content=enriched_content,
                    metadata=metadata or {}
                )
                
                logger.info(f"Successfully created embedding for node {node_id} of type {node_type}")
                
        except Exception as e:
            logger.error(f"Error creating node embedding: {str(e)}", exc_info=True)
            raise

    def get_graph_context(self, query: str, limit: int = 5, min_similarity: float = 0.6, max_depth: int = 2) -> Dict[str, Any]:
        """
        Retrieve relevant graph context using vector similarity and relationship traversal.
        
        Args:
            query: The search query text
            limit: Maximum number of primary nodes to return
            min_similarity: Minimum similarity score (0-1) for matching nodes
            max_depth: Maximum depth for relationship traversal
            
        Returns:
            Dict containing primary nodes, related nodes, and relationships
        """
        try:
            # Generate query embedding with metadata
            enriched_query = f"Query: {query}\nContext: Graph search for relevant nodes and relationships"
            response = self.openai.embeddings.create(
                model="text-embedding-3-small",
                input=enriched_query
            )
            query_embedding = response.data[0].embedding
            
            # Find similar nodes and their relationships in Neo4j
            with self.driver.session() as session:
                result = session.run("""
                // Find initial similar nodes
                MATCH (n)
                WHERE n.embedding IS NOT NULL
                WITH n, gds.similarity.cosine(n.embedding, $query_embedding) AS similarity
                WHERE similarity > $min_similarity
                
                // Traverse relationships up to max depth
                CALL apoc.path.subgraphNodes(n, {
                    relationshipFilter: "TAGGED|BELONGS_TO|HAS_ACCESS|MANAGES|OWNS",
                    maxLevel: $max_depth
                }) YIELD node as related
                
                // Collect relationships between nodes
                WITH n, similarity, related
                OPTIONAL MATCH path = (n)-[r*1..$max_depth]-(related)
                WHERE ALL(rel IN r WHERE type(rel) IN ['TAGGED', 'BELONGS_TO', 'HAS_ACCESS', 'MANAGES', 'OWNS'])
                
                // Aggregate results
                WITH n, similarity,
                     collect(DISTINCT {
                         node: related,
                         paths: collect(DISTINCT path)
                     }) as related_data
                
                // Return enriched data structure
                RETURN {
                    primary_node: {
                        id: n.id,
                        labels: labels(n),
                        name: n.name,
                        type: n.type,
                        content: n.text_content,
                        enriched_content: n.enriched_content,
                        metadata: n.embedding_metadata,
                        platform: n.platform,
                        environment: n.environment,
                        similarity: similarity
                    },
                    related_nodes: [node IN related_data | {
                        id: node.node.id,
                        labels: labels(node.node),
                        name: node.node.name,
                        type: node.node.type,
                        content: node.node.text_content,
                        metadata: node.node.embedding_metadata
                    }],
                    relationships: [path IN related_data.paths | {
                        path: [rel IN relationships(path) | {
                            type: type(rel),
                            properties: properties(rel),
                            start_node: startNode(rel).id,
                            end_node: endNode(rel).id
                        }]
                    }]
                } as result
                ORDER BY similarity DESC
                LIMIT $limit
                """, 
                query_embedding=query_embedding,
                limit=limit,
                min_similarity=min_similarity,
                max_depth=max_depth
                )
                
                results = [record["result"] for record in result]
                
                response_data = {
                    'query': query,
                    'primary_nodes': [r['primary_node'] for r in results],
                    'related_nodes': [node for r in results for node in r['related_nodes']],
                    'relationships': [rel for r in results for rel in r['relationships']],
                    'metadata': {
                        'total_primary_nodes': len(results),
                        'total_related_nodes': sum(len(r['related_nodes']) for r in results),
                        'max_similarity': max((r['primary_node']['similarity'] for r in results), default=0),
                        'min_similarity': min((r['primary_node']['similarity'] for r in results), default=0)
                    }
                }
                
                logger.info(
                    f"Retrieved graph context for query '{query}' with "
                    f"{response_data['metadata']['total_primary_nodes']} primary nodes and "
                    f"{response_data['metadata']['total_related_nodes']} related nodes"
                )
                
                return response_data
                
        except Exception as e:
            logger.error(f"Error retrieving graph context: {str(e)}", exc_info=True)
            raise

    def close(self):
        """Close the Neo4j driver connection."""
        try:
            self.driver.close()
        except Exception as e:
            logger.error(f"Error closing Neo4j connection: {str(e)}")

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
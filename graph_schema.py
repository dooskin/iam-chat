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
        self.uri = os.environ.get('NEO4J_URI')
        self.user = os.environ.get('NEO4J_USER')
        self.password = os.environ.get('NEO4J_PASSWORD')
        
        # Initialize OpenAI client
        openai_api_key = os.environ.get('OPENAI_API_KEY')
        if not openai_api_key:
            raise ValueError("Missing OpenAI API key")
        self.openai = OpenAI(api_key=openai_api_key)
        
        # Validate Neo4j credentials
        if not all([self.uri, self.user, self.password]):
            raise ValueError("Missing required Neo4j connection parameters")
            
        # Ensure URI has proper scheme and format
        if not self.uri.startswith(('neo4j://', 'neo4j+s://', 'bolt://', 'bolt+s://')):
            if '.databases.neo4j.io' in self.uri:
                self.uri = f"neo4j+s://{self.uri}"
            else:
                self.uri = f"bolt://{self.uri}"
            
        logger.info(f"Attempting to connect to Neo4j at {self.uri}")
        
        try:
            # Initialize Neo4j driver with robust error handling and retry configuration
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
                max_connection_lifetime=3600,  # 1 hour
                max_connection_pool_size=50,
                connection_acquisition_timeout=60,
                connection_timeout=30,
                encrypted=True if '+s://' in self.uri else False,
                trust='TRUST_SYSTEM_CA_SIGNED_CERTIFICATES'
            )
            
            # Test connection with retry logic
            retry_count = 0
            max_retries = 3
            while retry_count < max_retries:
                try:
                    self.driver.verify_connectivity()
                    logger.info("Successfully connected to Neo4j database")
                    break
                except Exception as e:
                    retry_count += 1
                    if retry_count == max_retries:
                        raise
                    logger.warning(f"Connection attempt {retry_count} failed: {str(e)}. Retrying...")
                    import time
                    time.sleep(2 ** retry_count)  # Exponential backoff
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {str(e)}")
            logger.error("Please verify your Neo4j URI, username, and password")
            raise

    def init_schema(self):
        """Initialize Neo4j schema with enhanced constraints and indexes for Cartography compatibility."""
        try:
            with self.driver.session() as session:
                # Base Cartography node constraints
                constraints = [
                    # Core asset management
                    "CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE",
                    "CREATE CONSTRAINT asset_type_unique IF NOT EXISTS FOR (a:Asset) REQUIRE (a.id, a.type) IS UNIQUE",
                    
                    # Identity and access management
                    "CREATE CONSTRAINT user_id IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE",
                    "CREATE CONSTRAINT group_id IF NOT EXISTS FOR (g:Group) REQUIRE g.id IS UNIQUE",
                    "CREATE CONSTRAINT role_id IF NOT EXISTS FOR (r:Role) REQUIRE r.id IS UNIQUE",
                    
                    # Cloud resources
                    "CREATE CONSTRAINT gcp_project_id IF NOT EXISTS FOR (p:GCPProject) REQUIRE p.id IS UNIQUE",
                    "CREATE CONSTRAINT service_account_id IF NOT EXISTS FOR (sa:ServiceAccount) REQUIRE sa.id IS UNIQUE",
                    "CREATE CONSTRAINT resource_id IF NOT EXISTS FOR (r:Resource) REQUIRE r.id IS UNIQUE",
                    
                    # HR system integration
                    "CREATE CONSTRAINT employee_id IF NOT EXISTS FOR (e:Employee) REQUIRE e.id IS UNIQUE",
                    "CREATE CONSTRAINT department_id IF NOT EXISTS FOR (d:Department) REQUIRE d.id IS UNIQUE",
                    
                    # SaaS integration
                    "CREATE CONSTRAINT salesforce_contact_id IF NOT EXISTS FOR (c:Contact) REQUIRE c.id IS UNIQUE",
                    "CREATE CONSTRAINT workday_employee_id IF NOT EXISTS FOR (w:WorkdayEmployee) REQUIRE w.id IS UNIQUE"
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
                    "CREATE TEXT INDEX asset_name_idx IF NOT EXISTS FOR (a:Asset) ON (a.name)",
                    "CREATE TEXT INDEX resource_name_idx IF NOT EXISTS FOR (r:Resource) ON (r.name)",
                    "CREATE TEXT INDEX user_email_idx IF NOT EXISTS FOR (u:User) ON (u.email)",
                    
                    # Asset management indexes
                    "CREATE INDEX asset_type_idx IF NOT EXISTS FOR (a:Asset) ON (a.type)",
                    "CREATE INDEX asset_platform_idx IF NOT EXISTS FOR (a:Asset) ON (a.platform)",
                    "CREATE INDEX asset_environment_idx IF NOT EXISTS FOR (a:Asset) ON (a.environment)",
                    "CREATE INDEX asset_last_sync_idx IF NOT EXISTS FOR (a:Asset) ON (a.lastupdated)",
                    
                    # Vector search indexes
                    "CREATE INDEX embedding_idx IF NOT EXISTS FOR (n) ON n.embedding",
                    "CREATE VECTOR INDEX vector_similarity_idx IF NOT EXISTS FOR (n) ON n.embedding OPTIONS {indexProvider: 'vector', similarity: 'cosine'}",
                    
                    # Relationship indexes
                    "CREATE INDEX relationship_type_idx IF NOT EXISTS FOR ()-[r]->() ON type(r)",
                    "CREATE INDEX relationship_timestamp_idx IF NOT EXISTS FOR ()-[r]->() ON r.lastupdated"
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
                YIELD name, labelsOrTypes, propertyKeys, type
                RETURN collect({
                    name: name,
                    labels: labelsOrTypes,
                    properties: propertyKeys,
                    type: type
                }) as constraints
                """)
                constraints = result.single()["constraints"]
                
                # Check indexes
                result = session.run("""
                SHOW INDEXES
                YIELD name, labelsOrTypes, properties, type, provider
                RETURN collect({
                    name: name,
                    labels: labelsOrTypes,
                    properties: properties,
                    type: type,
                    provider: provider
                }) as indexes
                """)
                indexes = result.single()["indexes"]
                
                # Validate required components
                required_labels = {'Asset', 'User', 'Role', 'Group', 'ServiceAccount', 'GCPProject'}
                required_indexes = {'vector_similarity_idx', 'asset_type_idx', 'embedding_idx'}
                
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

    def create_or_update_asset(self, asset_data: Dict[str, Any]) -> None:
        """Create or update an asset node with enhanced Cartography compatibility."""
        try:
            with self.driver.session() as session:
                # Base asset creation/update query
                query = """
                MERGE (a:Asset {id: $id})
                SET 
                    a.name = $name,
                    a.type = $type,
                    a.platform = $platform,
                    a.metadata = $metadata,
                    a.last_updated = timestamp(),
                    a.firstseen = CASE
                        WHEN NOT EXISTS(a.firstseen) THEN timestamp()
                        ELSE a.firstseen
                    END,
                    a.lastupdated = timestamp(),
                    a.location = $location,
                    a.environment = $environment,
                    a.owner = $owner,
                    a.tag_list = $tags,
                    a:ASSET  // Cartography standard label
                WITH a
                CALL {
                    WITH a
                    MATCH (a)-[r:TAGGED]->(t:Tag)
                    WHERE NOT t.name IN $tags
                    DELETE r
                }
                WITH a
                UNWIND $tags as tag_name
                MERGE (t:Tag {name: tag_name})
                MERGE (a)-[:TAGGED]->(t)
                """
                
                session.run(
                    query,
                    id=asset_data['id'],
                    name=asset_data['name'],
                    type=asset_data['type'],
                    platform=asset_data['platform'],
                    metadata=json.dumps(asset_data.get('metadata', {})),
                    location=asset_data.get('location', ''),
                    environment=asset_data.get('environment', 'production'),
                    owner=asset_data.get('owner', ''),
                    tags=asset_data.get('tags', [])
                )
                
                # Process relationships if defined
                if 'relationships' in asset_data:
                    self._create_relationships(asset_data['id'], asset_data['relationships'])
                
        except Exception as e:
            logger.error(f"Error creating/updating asset: {str(e)}")
            raise

    def _create_relationships(self, source_id: str, relationships: List[Dict[str, str]]) -> None:
        """Create relationships between assets."""
        try:
            with self.driver.session() as session:
                for rel in relationships:
                    query = """
                    MATCH (a:Asset {id: $source_id})
                    MATCH (b:Asset {id: $target_id})
                    MERGE (a)-[r:$rel_type]->(b)
                    SET r.lastupdated = timestamp()
                    """
                    session.run(
                        query,
                        source_id=source_id,
                        target_id=rel['target_id'],
                        rel_type=rel['type']
                    )
        except Exception as e:
            logger.error(f"Error creating relationships: {str(e)}")
            raise

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
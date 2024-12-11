import os
import json
import logging
from neo4j import GraphDatabase
from openai import OpenAI
from typing import Dict, Any, List, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GraphSchema:
    """Manages Neo4j graph schema and operations with Cartography compatibility."""
    
    def __init__(self):
        """Initialize Neo4j connection and OpenAI client."""
        self.uri = os.environ.get('NEO4J_URI', '').strip()
        self.user = os.environ.get('NEO4J_USER', '').strip()
        self.password = os.environ.get('NEO4J_PASSWORD', '').strip()
        
        if not all([self.uri, self.user, self.password]):
            raise ValueError("Missing required Neo4j connection parameters")
            
        # Ensure URI has proper scheme
        if not self.uri.startswith(('neo4j://', 'neo4j+s://', 'bolt://', 'bolt+s://')):
            self.uri = f"neo4j+s://{self.uri}"
            
        logger.info(f"Attempting to connect to Neo4j at {self.uri}")
        
        try:
            # Initialize Neo4j driver with connection pool and retry settings
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
                max_connection_lifetime=3600,
                max_connection_pool_size=50,
                connection_acquisition_timeout=60
            )
            # Verify connection
            self.driver.verify_connectivity()
            logger.info("Successfully connected to Neo4j database")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {str(e)}")
            logger.error("Please verify your Neo4j URI, username, and password")
            raise
        
        # Initialize OpenAI client
        self.openai = OpenAI(api_key=os.environ.get('OPENAI_API_KEY'))
        if not os.environ.get('OPENAI_API_KEY'):
            raise ValueError("Missing OpenAI API key")

    def init_schema(self):
        """Initialize Neo4j schema with constraints and indexes for Cartography compatibility."""
        try:
            with self.driver.session() as session:
                # Create constraints for core node types
                constraints = [
                    "CREATE CONSTRAINT user_id IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE",
                    "CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE",
                    "CREATE CONSTRAINT role_id IF NOT EXISTS FOR (r:Role) REQUIRE r.id IS UNIQUE",
                    "CREATE CONSTRAINT group_id IF NOT EXISTS FOR (g:Group) REQUIRE g.id IS UNIQUE",
                    "CREATE CONSTRAINT department_id IF NOT EXISTS FOR (d:Department) REQUIRE d.id IS UNIQUE"
                ]
                
                for constraint in constraints:
                    try:
                        session.run(constraint)
                    except Exception as e:
                        logger.error(f"Error creating constraint: {str(e)}")
                        # Continue with other constraints even if one fails
                        continue
                
                # Create indexes for frequently queried properties
                indexes = [
                    "CREATE INDEX user_email_idx IF NOT EXISTS FOR (u:User) ON (u.email)",
                    "CREATE INDEX asset_type_idx IF NOT EXISTS FOR (a:Asset) ON (a.type)",
                    "CREATE INDEX node_embedding_idx IF NOT EXISTS FOR (n:Node) ON (n.embedding)"
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

    def test_connection(self) -> bool:
        """Test Neo4j connection and basic operations."""
        try:
            with self.driver.session() as session:
                # Test basic query
                result = session.run("MATCH (n) RETURN count(n) as count")
                count = result.single()["count"]
                logger.info(f"Connection test successful. Found {count} nodes in database.")
                return True
        except Exception as e:
            logger.error(f"Connection test failed: {str(e)}")
            return False

    def create_or_update_asset(self, asset_data: Dict[str, Any]) -> None:
        """Create or update an asset node with Cartography compatibility."""
        try:
            with self.driver.session() as session:
                query = """
                MERGE (a:Asset {id: $id})
                SET 
                    a.name = $name,
                    a.type = $type,
                    a.platform = $platform,
                    a.metadata = $metadata,
                    a.last_updated = timestamp()
                """
                session.run(
                    query,
                    id=asset_data['id'],
                    name=asset_data['name'],
                    type=asset_data['type'],
                    platform=asset_data['platform'],
                    metadata=json.dumps(asset_data.get('metadata', {}))
                )
        except Exception as e:
            logger.error(f"Error creating/updating asset: {str(e)}")
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

    def get_graph_context(self, query: str, limit: int = 5) -> Dict[str, List[Dict[str, Any]]]:
        """Retrieve relevant graph context using vector similarity."""
        try:
            # Generate query embedding
            response = self.openai.embeddings.create(
                model="text-embedding-3-small",
                input=query
            )
            query_embedding = response.data[0].embedding
            
            # Find similar nodes in Neo4j
            with self.driver.session() as session:
                result = session.run("""
                MATCH (n)
                WHERE n.embedding IS NOT NULL
                WITH n, gds.similarity.cosine(n.embedding, $query_embedding) AS similarity
                WHERE similarity > 0.7
                RETURN n.id as id, labels(n) as labels, n.name as name, 
                       n.type as type, n.text_content as content,
                       similarity
                ORDER BY similarity DESC
                LIMIT $limit
                """, query_embedding=query_embedding, limit=limit)
                
                nodes = []
                for record in result:
                    nodes.append({
                        'id': record['id'],
                        'labels': record['labels'],
                        'name': record['name'],
                        'type': record['type'],
                        'content': record['content'],
                        'similarity': record['similarity']
                    })
                
                return {
                    'primary_nodes': nodes,
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
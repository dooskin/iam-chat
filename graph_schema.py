import os
import logging
from datetime import datetime
from neo4j import GraphDatabase
from typing import Optional, Dict, Any, List
import openai
from dataclasses import dataclass
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GraphSchema:
    """Manages Neo4j graph schema and operations for the RAG system."""
    
    def __init__(self):
        """Initialize Neo4j connection and configure OpenAI."""
        self.uri = os.environ.get('NEO4J_URI')
        self.user = os.environ.get('NEO4J_USER')
        self.password = os.environ.get('NEO4J_PASSWORD')
        
        # Initialize Neo4j driver
        self.driver = GraphDatabase.driver(
            self.uri,
            auth=(self.user, self.password)
        )
        
        # Initialize OpenAI client
        openai.api_key = os.environ.get('OPENAI_API_KEY')

    def init_schema(self):
        """Initialize Neo4j schema with constraints and indexes for Cartography compatibility."""
        with self.driver.session() as session:
            # Create constraints for unique identifiers
            constraints = [
                # Asset nodes (Cloud Resources)
                "CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (n:Asset) REQUIRE n.id IS UNIQUE",
                "CREATE CONSTRAINT asset_name IF NOT EXISTS FOR (n:Asset) REQUIRE n.name IS UNIQUE",
                
                # User nodes
                "CREATE CONSTRAINT user_id IF NOT EXISTS FOR (n:User) REQUIRE n.id IS UNIQUE",
                "CREATE CONSTRAINT user_email IF NOT EXISTS FOR (n:User) REQUIRE n.email IS UNIQUE",
                
                # Group nodes (IAM & HR)
                "CREATE CONSTRAINT group_id IF NOT EXISTS FOR (n:Group) REQUIRE n.id IS UNIQUE",
                "CREATE CONSTRAINT group_name IF NOT EXISTS FOR (n:Group) REQUIRE n.name IS UNIQUE",
                
                # Role nodes (IAM)
                "CREATE CONSTRAINT role_id IF NOT EXISTS FOR (n:Role) REQUIRE n.id IS UNIQUE",
                "CREATE CONSTRAINT role_name IF NOT EXISTS FOR (n:Role) REQUIRE n.name IS UNIQUE",
                
                # Department nodes (HR)
                "CREATE CONSTRAINT dept_id IF NOT EXISTS FOR (n:Department) REQUIRE n.id IS UNIQUE",
                "CREATE CONSTRAINT dept_name IF NOT EXISTS FOR (n:Department) REQUIRE n.name IS UNIQUE",
                
                # Project nodes (GCP)
                "CREATE CONSTRAINT project_id IF NOT EXISTS FOR (n:GCPProject) REQUIRE n.id IS UNIQUE",
                "CREATE CONSTRAINT project_name IF NOT EXISTS FOR (n:GCPProject) REQUIRE n.name IS UNIQUE",
                
                # Service Account nodes (GCP)
                "CREATE CONSTRAINT sa_id IF NOT EXISTS FOR (n:ServiceAccount) REQUIRE n.id IS UNIQUE",
                "CREATE CONSTRAINT sa_email IF NOT EXISTS FOR (n:ServiceAccount) REQUIRE n.email IS UNIQUE",
                
                # Vector embedding nodes (RAG)
                "CREATE CONSTRAINT embedding_id IF NOT EXISTS FOR (n:Embedding) REQUIRE n.id IS UNIQUE",
                
                # HR System nodes (Workday/Salesforce)
                "CREATE CONSTRAINT hr_system_id IF NOT EXISTS FOR (n:HRSystem) REQUIRE n.id IS UNIQUE",
                "CREATE CONSTRAINT hr_system_name IF NOT EXISTS FOR (n:HRSystem) REQUIRE n.name IS UNIQUE"
            ]
            
            # Create indexes for performance
            indexes = [
                "CREATE INDEX asset_type_idx IF NOT EXISTS FOR (n:Asset) ON (n.type)",
                "CREATE INDEX user_role_idx IF NOT EXISTS FOR (n:User) ON (n.role)",
                "CREATE INDEX embedding_type_idx IF NOT EXISTS FOR (n:Embedding) ON (n.type)",
                "CREATE INDEX dept_name_idx IF NOT EXISTS FOR (n:Department) ON (n.name)"
            ]
            
            # Execute schema updates
            for constraint in constraints:
                try:
                    session.run(constraint)
                except Exception as e:
                    logger.error(f"Error creating constraint: {str(e)}")
                    
            for index in indexes:
                try:
                    session.run(index)
                except Exception as e:
                    logger.error(f"Error creating index: {str(e)}")

    def store_embedding(self, node_id: str, node_type: str, vector: List[float]) -> None:
        """Store vector embedding for a node."""
        with self.driver.session() as session:
            query = """
            MATCH (n {id: $node_id})
            MERGE (n)-[:HAS_EMBEDDING]->(e:Embedding {id: $embedding_id})
            SET e.vector = $vector,
                e.type = $node_type,
                e.created_at = timestamp()
            """
            session.run(query,
                       node_id=node_id,
                       embedding_id=f"{node_id}_embedding",
                       vector=vector,
                       node_type=node_type)

    def create_node_embedding(self, node_id: str, node_type: str, text_content: str) -> None:
        """
        Create and store vector embedding for a node's text content.
        
        Args:
            node_id: Unique identifier of the node
            node_type: Type of the node (e.g., 'User', 'Asset', 'Policy')
            text_content: Text to be embedded
        """
        try:
            # Generate embedding using OpenAI's API
            response = openai.Embedding.create(
                input=text_content,
                model="text-embedding-ada-002"
            )
            embedding_vector = response['data'][0]['embedding']
            
            # Store the embedding
            self.store_embedding(node_id, node_type, embedding_vector)
            
        except Exception as e:
            logger.error(f"Error creating embedding for node {node_id}: {str(e)}")
            raise

    def query_similar_nodes(self, embedding: List[float], node_type: Optional[str] = None,
                          limit: int = 5, min_similarity: float = 0.7) -> List[Dict[str, Any]]:
        """
        Query nodes with similar embeddings using cosine similarity and graph traversal.
        
        Args:
            embedding: Vector embedding to compare against
            node_type: Optional type of node to filter by
            limit: Maximum number of results to return
            min_similarity: Minimum similarity threshold (0-1)
            
        Returns:
            List of nodes with their similarity scores and related nodes
        """
        with self.driver.session() as session:
            # Enhanced query that includes related nodes and metadata
            query = """
            MATCH (n)-[:HAS_EMBEDDING]->(e:Embedding)
            WHERE $node_type IS NULL OR e.type = $node_type
            WITH n, e, gds.similarity.cosine(e.vector, $embedding) AS similarity
            WHERE similarity >= $min_similarity
            
            // Get related nodes within 2 hops
            OPTIONAL MATCH (n)-[r:BELONGS_TO|MANAGES|HAS_ACCESS|MEMBER_OF*1..2]-(related)
            WHERE NOT related:Embedding
            
            WITH n, similarity, collect(DISTINCT {
                node: related,
                relationship_type: type(r),
                direction: CASE WHEN startNode(r) = n THEN 'outgoing' ELSE 'incoming' END
            }) as connections
            
            ORDER BY similarity DESC
            LIMIT $limit
            
            RETURN {
                node: n,
                similarity: similarity,
                metadata: n.metadata,
                connections: connections
            } as result
            """
            
            result = session.run(query,
                               embedding=embedding,
                               node_type=node_type,
                               limit=limit,
                               min_similarity=min_similarity)
            
            return [record["result"] for record in result]

    def get_graph_context(self, query: str, limit: int = 5) -> Dict[str, Any]:
        """
        Get relevant graph context for a query using vector similarity and graph traversal.
        
        Args:
            query: User's question or request
            limit: Maximum number of primary nodes to return
            
        Returns:
            Dictionary containing relevant nodes and their relationships
        """
        try:
            # Generate embedding for the query
            response = openai.Embedding.create(
                input=query,
                model="text-embedding-ada-002"
            )
            query_embedding = response['data'][0]['embedding']
            
            # Find similar nodes
            similar_nodes = self.query_similar_nodes(
                embedding=query_embedding,
                limit=limit,
                min_similarity=0.7
            )
            
            # Extract unique node IDs from the results including connected nodes
            node_ids = set()
            for result in similar_nodes:
                node_ids.add(result['node']['id'])
                for conn in result.get('connections', []):
                    if conn['node']:
                        node_ids.add(conn['node']['id'])
            
            return {
                'primary_nodes': similar_nodes,
                'node_count': len(node_ids),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting graph context: {str(e)}")
            raise
            
    def integrate_hr_data(self, hr_data: Dict[str, Any], source_system: str) -> None:
        """
        Integrate HR data from Workday/Salesforce into the graph.
        
        Args:
            hr_data: Dictionary containing HR data
            source_system: Name of the source system (e.g., 'workday', 'salesforce')
        """
        with self.driver.session() as session:
            query = """
            MERGE (sys:HRSystem {name: $source})
            SET sys.last_sync = timestamp()
            
            WITH sys
            UNWIND $data as record
            
            // Create or update user
            MERGE (u:User {email: record.email})
            SET 
                u.name = record.name,
                u.employee_id = record.employee_id,
                u.title = record.title,
                u.last_updated = timestamp(),
                u.source_system = $source
            
            // Create or update department
            MERGE (d:Department {name: record.department})
            SET d.last_updated = timestamp()
            
            // Create relationships
            MERGE (u)-[:BELONGS_TO]->(d)
            MERGE (u)-[:SOURCED_FROM]->(sys)
            
            // Handle manager relationship
            WITH u, record
            MATCH (manager:User {email: record.manager_email})
            MERGE (u)-[:REPORTS_TO]->(manager)
            """
            
            session.run(query, source=source_system, data=hr_data)

    def close(self):
        """Close the Neo4j driver connection."""
        self.driver.close()

    def create_or_update_asset(self, asset_data: Dict[str, Any]) -> None:
        """Create or update an asset node with relationships."""
        with self.driver.session() as session:
            query = """
            MERGE (a:Asset {id: $id})
            SET 
                a.name = $name,
                a.type = $type,
                a.platform = $platform,
                a.last_updated = timestamp(),
                a.metadata = $metadata
            """
            session.run(query, 
                       id=asset_data['id'],
                       name=asset_data['name'],
                       type=asset_data['type'],
                       platform=asset_data.get('platform', 'unknown'),
                       metadata=json.dumps(asset_data.get('metadata', {})))

    def create_or_update_user(self, user_data: Dict[str, Any]) -> None:
        """Create or update a user node with HR data."""
        with self.driver.session() as session:
            query = """
            MERGE (u:User {id: $id})
            SET 
                u.email = $email,
                u.name = $name,
                u.title = $title,
                u.department = $department,
                u.last_updated = timestamp(),
                u.metadata = $metadata
            WITH u
            MATCH (d:Department {name: $department})
            MERGE (u)-[:BELONGS_TO]->(d)
            """
            session.run(query,
                       id=user_data['id'],
                       email=user_data['email'],
                       name=user_data['name'],
                       title=user_data.get('title', ''),
                       department=user_data.get('department', 'Unknown'),
                       metadata=json.dumps(user_data.get('metadata', {})))
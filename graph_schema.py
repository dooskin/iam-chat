from typing import Dict, List, Optional, Any
from neo4j import GraphDatabase
import logging
import os

class GraphSchema:
    """Handles Neo4j graph database schema and operations for the RAG system."""
    
    def __init__(self):
        """Initialize Neo4j connection using environment variables."""
        self.uri = os.environ.get('NEO4J_URI')
        self.user = os.environ.get('NEO4J_USER')
        self.password = os.environ.get('NEO4J_PASSWORD')
        self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
        self.logger = logging.getLogger(__name__)

    def close(self):
        """Close the Neo4j driver connection."""
        self.driver.close()

    def init_schema(self):
        """Initialize the graph database schema with constraints and indexes."""
        with self.driver.session() as session:
            # Core entity constraints
            constraints = [
                "CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE",
                "CREATE CONSTRAINT resource_id IF NOT EXISTS FOR (r:Resource) REQUIRE r.id IS UNIQUE",
                "CREATE CONSTRAINT service_account_id IF NOT EXISTS FOR (sa:ServiceAccount) REQUIRE sa.id IS UNIQUE",
                "CREATE CONSTRAINT role_id IF NOT EXISTS FOR (r:Role) REQUIRE r.id IS UNIQUE",
                "CREATE CONSTRAINT project_id IF NOT EXISTS FOR (p:Project) REQUIRE p.id IS UNIQUE"
            ]
            
            # Performance indexes
            indexes = [
                "CREATE INDEX asset_type IF NOT EXISTS FOR (a:Asset) ON (a.type)",
                "CREATE INDEX resource_name IF NOT EXISTS FOR (r:Resource) ON (r.name)",
                "CREATE INDEX service_account_email IF NOT EXISTS FOR (sa:ServiceAccount) ON (sa.email)"
            ]
            
            for constraint in constraints:
                try:
                    session.run(constraint)
                except Exception as e:
                    self.logger.error(f"Error creating constraint: {str(e)}")
                    
            for index in indexes:
                try:
                    session.run(index)
                except Exception as e:
                    self.logger.error(f"Error creating index: {str(e)}")

    def create_or_update_asset(self, asset_data: Dict[str, Any]) -> None:
        """Create or update an asset node with its relationships."""
        with self.driver.session() as session:
            # Base node creation query
            query = """
            MERGE (a:Asset {id: $id})
            SET a += $properties
            WITH a
            """
            
            # Add relationships if specified
            if asset_data.get('relationships'):
                for rel in asset_data['relationships']:
                    query += f"""
                    MATCH (target:{rel.get('target_type', 'Asset')} {{id: $rel_{rel['target_id']}_id}})
                    MERGE (a)-[r:{rel['type']}]->(target)
                    SET r += $rel_{rel['target_id']}_props
                    """
            
            # Prepare parameters
            params = {
                'id': asset_data['id'],
                'properties': {
                    'name': asset_data.get('name', ''),
                    'type': asset_data.get('type', ''),
                    'platform': asset_data.get('platform', ''),
                    'metadata': asset_data.get('metadata', {})
                }
            }
            
            # Add relationship parameters
            if asset_data.get('relationships'):
                for rel in asset_data['relationships']:
                    params[f"rel_{rel['target_id']}_id"] = rel['target_id']
                    params[f"rel_{rel['target_id']}_props"] = rel.get('properties', {})
            
            try:
                session.run(query, params)
            except Exception as e:
                self.logger.error(f"Error creating/updating asset: {str(e)}")
                raise

    def create_node_embedding(self, node_id: str, node_type: str, text_content: str, 
                            metadata: Optional[Dict[str, Any]] = None) -> None:
        """Create or update node embeddings for RAG operations."""
        with self.driver.session() as session:
            query = """
            MATCH (n {id: $node_id})
            SET n.embedding = $embedding,
                n.text_content = $text_content,
                n.last_embedded = timestamp()
            """
            
            try:
                # TODO: Implement actual embedding generation using OpenAI or similar
                # For now, we'll just store the text content
                session.run(query, {
                    'node_id': node_id,
                    'text_content': text_content,
                    'embedding': []  # Placeholder for actual embeddings
                })
            except Exception as e:
                self.logger.error(f"Error creating node embedding: {str(e)}")
                raise

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

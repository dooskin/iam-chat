import os
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from gremlin_python.process.anonymous_traversal import traversal
from gremlin_python.driver.driver_remote_connection import DriverRemoteConnection
from gremlin_python.process.graph_traversal import __
from gremlin_python.process.traversal import T, P, Cardinality
from openai import OpenAI

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NeptuneGraphSchema:
    """Graph database schema manager with vector embeddings support using AWS Neptune."""
    
    def __init__(self):
        """Initialize Neptune connection and OpenAI client."""
        try:
            # Get Neptune configuration from environment
            self.endpoint = os.getenv('NEPTUNE_ENDPOINT')
            if not self.endpoint:
                raise ValueError("NEPTUNE_ENDPOINT environment variable is required")
            
            # Initialize OpenAI client for embeddings
            self.openai = OpenAI()
            logger.info("OpenAI client initialized successfully")
            
            # Initialize Gremlin connection
            self.conn = DriverRemoteConnection(
                f'wss://{self.endpoint}:8182/gremlin',
                'g'
            )
            self.g = traversal().withRemote(self.conn)
            logger.info("Successfully connected to Neptune")
            
        except Exception as e:
            logger.error(f"Failed to initialize Neptune connection: {str(e)}")
            raise
    
    def init_schema(self) -> bool:
        """Initialize the graph database schema with Cartography compatibility."""
        try:
            # Neptune doesn't require explicit schema creation, but we'll
            # create necessary property indices for performance
            vertex_labels = [
                'User', 'Resource', 'Group', 'Role', 'Application',
                'Device', 'Network'
            ]
            
            for label in vertex_labels:
                # Create indices for common properties
                self.g.V().hasLabel(label).property('id').toList()
                self.g.V().hasLabel(label).property('lastupdated').toList()
                self.g.V().hasLabel(label).property('firstseen').toList()
                
            logger.info("Successfully initialized Neptune schema")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize schema: {str(e)}")
            return False
    
    def validate_schema(self) -> bool:
        """Validate the graph database schema."""
        try:
            # Check if we can create and query vertices with required properties
            test_id = f"test_{datetime.now().timestamp()}"
            
            # Create test vertex
            self.g.addV('TestNode')\
                .property('id', test_id)\
                .property('lastupdated', datetime.now().isoformat())\
                .property('firstseen', datetime.now().isoformat())\
                .next()
            
            # Verify vertex creation
            result = self.g.V().hasLabel('TestNode').has('id', test_id).toList()
            
            # Clean up test vertex
            self.g.V().hasLabel('TestNode').has('id', test_id).drop().iterate()
            
            logger.info("Schema validation successful")
            return len(result) > 0
            
        except Exception as e:
            logger.error(f"Schema validation failed: {str(e)}")
            return False
    
    def create_node_embedding(
        self,
        node_id: str,
        node_type: str,
        text_content: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Create vector embedding for a node using OpenAI."""
        try:
            # Generate embedding using OpenAI
            response = self.openai.embeddings.create(
                model="text-embedding-3-small",
                input=text_content
            )
            embedding = response.data[0].embedding
            
            # Prepare metadata
            timestamp = datetime.now().isoformat()
            properties = {
                'id': node_id,
                'text_content': text_content,
                'embedding': json.dumps(embedding),  # Neptune requires JSON string for arrays
                'embedding_model': 'text-embedding-3-small',
                'last_updated': timestamp,
                'lastupdated': int(datetime.now().timestamp()),  # Cartography compatibility
                'firstseen': timestamp
            }
            
            if metadata:
                properties.update(metadata)
            
            # Create or update vertex with embedding
            vertex = self.g.V().has(node_type, 'id', node_id)
            if vertex.hasNext():
                # Update existing vertex
                for key, value in properties.items():
                    vertex.property(Cardinality.single, key, value).next()
            else:
                # Create new vertex
                vertex = self.g.addV(node_type)
                for key, value in properties.items():
                    vertex.property(key, value)
                vertex.next()
            
            logger.info(f"Successfully created embedding for node {node_id} of type {node_type}")
            
        except Exception as e:
            logger.error(f"Error creating node embedding: {str(e)}")
            raise
    
    def get_graph_context(
        self,
        query: str,
        limit: int = 5,
        max_hops: int = 2,
        score_threshold: float = 0.6
    ) -> Dict[str, Any]:
        """
        Retrieve relevant graph context using similarity search and relationship traversal.
        
        This implementation uses Neptune's native vector similarity search capabilities
        combined with Gremlin traversals for graph exploration.
        """
        try:
            # Generate query embedding
            query_embedding = self.openai.embeddings.create(
                model="text-embedding-3-small",
                input=query
            ).data[0].embedding
            
            # Find similar nodes using vector similarity
            similar_vertices = (
                self.g.V()
                .has('embedding')
                .order()
                .by(lambda: f"vectorSimilarity({json.dumps(query_embedding)}, embedding)")
                .limit(limit)
                .project('id', 'label', 'properties', 'similarity')
                .by('id')
                .by(T.label)
                .by(__.valueMap().by(__.unfold()))
                .toList()
            )
            
            # Collect context through relationship traversal
            context_data = {
                'query': query,
                'query_time': datetime.now().isoformat(),
                'primary_nodes': [],
                'context_graph': {
                    'nodes': set(),
                    'relationships': []
                },
                'metadata': {
                    'max_similarity': 0.0,
                    'total_contexts': 0,
                    'total_related_nodes': 0,
                    'total_relationships': 0
                }
            }
            
            # Process similar vertices and their contexts
            for vertex in similar_vertices:
                # Add primary node
                context_data['primary_nodes'].append({
                    'id': vertex['id'],
                    'type': vertex['label'],
                    'properties': vertex['properties'],
                    'similarity': vertex['similarity']
                })
                
                # Update max similarity
                context_data['metadata']['max_similarity'] = max(
                    context_data['metadata']['max_similarity'],
                    vertex['similarity']
                )
                
                # Explore related nodes within max_hops
                related = (
                    self.g.V().has('id', vertex['id'])
                    .repeat(__.both().simplePath())
                    .times(max_hops)
                    .dedup()
                    .project('id', 'label', 'properties')
                    .by('id')
                    .by(T.label)
                    .by(__.valueMap().by(__.unfold()))
                    .toList()
                )
                
                # Add related nodes to context
                for node in related:
                    context_data['context_graph']['nodes'].add(
                        json.dumps({
                            'id': node['id'],
                            'type': node['label'],
                            'properties': node['properties']
                        })
                    )
                
                # Collect relationships
                relationships = (
                    self.g.V().has('id', vertex['id'])
                    .repeat(__.bothE().subgraph('sg').otherV())
                    .times(max_hops)
                    .cap('sg')
                    .unfold()
                    .project('id', 'label', 'properties', 'fromV', 'toV')
                    .by(T.id)
                    .by(T.label)
                    .by(__.valueMap().by(__.unfold()))
                    .by(__.outV().values('id'))
                    .by(__.inV().values('id'))
                    .toList()
                )
                
                # Add relationships to context
                for rel in relationships:
                    context_data['context_graph']['relationships'].append({
                        'id': rel['id'],
                        'type': rel['label'],
                        'properties': rel['properties'],
                        'from_node': rel['fromV'],
                        'to_node': rel['toV']
                    })
            
            # Convert nodes set to list and update metadata
            context_data['context_graph']['nodes'] = [
                json.loads(node) for node in context_data['context_graph']['nodes']
            ]
            
            context_data['metadata'].update({
                'total_contexts': len(context_data['primary_nodes']),
                'total_related_nodes': len(context_data['context_graph']['nodes']),
                'total_relationships': len(context_data['context_graph']['relationships'])
            })
            
            return context_data
            
        except Exception as e:
            logger.error(f"Error retrieving graph context: {str(e)}")
            raise
    
    def close(self):
        """Close the Neptune connection."""
        try:
            if hasattr(self, 'conn'):
                self.conn.close()
                logger.info("Neptune connection closed")
        except Exception as e:
            logger.error(f"Error closing Neptune connection: {str(e)}")

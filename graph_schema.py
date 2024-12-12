import os
import logging
import json
import boto3
import asyncio
import aiohttp
import ssl
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, TypeVar
from botocore.config import Config
from gremlin_python.driver.driver_remote_connection import DriverRemoteConnection
from gremlin_python.process.anonymous_traversal import traversal
from gremlin_python.process.graph_traversal import __
from gremlin_python.driver.protocol import GremlinServerError
from gremlin_python.driver import serializer
from gremlin_python.driver.aiohttp.transport import AiohttpTransport
from aiohttp.client_exceptions import ClientConnectorError, ClientError
from openai import OpenAI
from gremlin_python.process.traversal import Order
from gremlin_python.structure.graph import Graph
from gremlin_python.structure.io.graphson import GraphSONReader
from gremlin_python.structure.io.graphson import GraphSONWriter
from java.lang import String
from java.lang import Long

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GraphSchema:
    """Graph database schema manager with vector embeddings support for Neptune."""
    
    def __init__(self):
        """Initialize Neptune connection and OpenAI client."""
        try:
            # Get configuration from environment
            self.endpoint = os.getenv('NEPTUNE_ENDPOINT')
            if not self.endpoint:
                raise ValueError("NEPTUNE_ENDPOINT environment variable is required")
            
            # Initialize OpenAI client
            self.openai = OpenAI()
            logger.info("OpenAI client initialized successfully")
            
            # Initialize Neptune driver with retry logic
            self._init_neptune_connection()
            
        except Exception as e:
            logger.error(f"Failed to initialize Neptune connection: {str(e)}")
            raise

    def _init_neptune_connection(self):
        """Initialize Neptune connection with retry logic."""
        retry_count = 0
        max_retries = 3
        last_error = None

        while retry_count < max_retries:
            try:
                # Configure SSL context
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = True
                ssl_context.verify_mode = ssl.CERT_REQUIRED

                # Initialize connection
                self.connection = DriverRemoteConnection(
                    f'wss://{self.endpoint}:8182/gremlin',
                    'g',
                    message_serializer=serializer.GraphSONSerializersV2d0(),
                    transport_factory=lambda: AiohttpTransport(
                        call_from_event_loop=True,
                        read_timeout=15,
                        write_timeout=15,
                        ssl=ssl_context
                    )
                )
                
                # Create traversal source
                self.g = traversal().withRemote(self.connection)
                
                # Test connection
                self.g.V().limit(1).count().next()
                logger.info("Successfully connected to Neptune")
                return
                
            except Exception as e:
                retry_count += 1
                last_error = str(e)
                
                if retry_count < max_retries:
                    wait_time = min(2 ** retry_count, 30)
                    logger.warning(f"Connection attempt {retry_count} failed: {last_error}")
                    logger.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    raise Exception(f"Failed to establish Neptune connection after {max_retries} attempts: {last_error}")

    def init_schema(self):
        """Initialize the graph database schema with Cartography compatibility."""
        try:
            # Create property keys and indices for core vertex labels
            vertex_labels = ['User', 'Resource', 'Group', 'Role', 'Application']
            
            for label in vertex_labels:
                # Create indices for common properties
                self.g.management().makeLabelConstraint(label).add().next()
                self.g.management().makePropertyKey('id').dataType(String.class).make()
                self.g.management().makePropertyKey('name').dataType(String.class).make()
                self.g.management().makePropertyKey('lastupdated').dataType(Long.class).make()
                self.g.management().makePropertyKey('firstseen').dataType(Long.class).make()
                
                # Create composite indices
                self.g.management().buildIndex(f'{label.lower()}_id_idx')\
                    .addKey('id')\
                    .indexOnly(label)\
                    .unique()\
                    .buildCompositeIndex()
                
                logger.info(f"Created schema elements for {label}")
            
            # Create indices for relationships
            rel_types = ["HAS_PERMISSION", "BELONGS_TO", "MANAGES", "OWNS", "ACCESSES"]
            for rel_type in rel_types:
                self.g.management().makeEdgeLabel(rel_type).make()
                logger.info(f"Created edge label: {rel_type}")
            
            logger.info("Successfully initialized Neptune schema")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize schema: {str(e)}")
            raise

    def create_node_embedding(self, node_id: str, node_type: str, text_content: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Create vector embedding for a node using OpenAI."""
        try:
            # Generate embedding using OpenAI
            response = self.openai.embeddings.create(
                model="text-embedding-3-small",
                input=text_content
            )
            embedding = response.data[0].embedding
            
            # Prepare metadata
            node_metadata = {
                'last_updated': datetime.now().isoformat(),
                'content_length': len(text_content),
                'embedding_model': 'text-embedding-3-small'
            }
            if metadata:
                node_metadata.update(metadata)
            
            # Store node with embedding in Neptune
            properties = {
                'id': node_id,
                'text_content': text_content,
                'embedding': embedding,
                'last_updated': node_metadata['last_updated'],
                'content_length': node_metadata['content_length'],
                'embedding_model': node_metadata['embedding_model'],
                'lastupdated': int(datetime.now().timestamp() * 1000),
                'firstseen': int(datetime.now().timestamp() * 1000)
            }
            if metadata:
                properties.update(metadata)
            
            # Create or update vertex
            self.g.addV(node_type)\
                .property('id', node_id)\
                .property('text_content', text_content)\
                .property('embedding', embedding)\
                .property('last_updated', properties['last_updated'])\
                .property('content_length', properties['content_length'])\
                .property('embedding_model', properties['embedding_model'])\
                .property('lastupdated', properties['lastupdated'])\
                .property('firstseen', properties['firstseen'])\
                .next()
            
            logger.info(f"Successfully created embedding for node {node_id} of type {node_type}")
                
        except Exception as e:
            logger.error(f"Error creating node embedding: {str(e)}")
            raise

    def get_graph_context(self, query: str, limit: int = 5, max_hops: int = 2, score_threshold: float = 0.6) -> Dict[str, Any]:
        """Retrieve relevant graph context using similarity search and relationship traversal."""
        try:
            # Generate query embedding
            query_embedding = self.openai.embeddings.create(
                model="text-embedding-3-small",
                input=query
            ).data[0].embedding
            
            # Find similar nodes using vector similarity
            similar_nodes = self.g.V()\
                .has('embedding')\
                .order()\
                .by(__.coalesce(
                    __.values('embedding').math('cosineSimilarity(' + str(query_embedding) + ')'),
                    __.constant(-1)
                ), Order.desc)\
                .limit(limit)\
                .project('id', 'label', 'properties', 'similarity')\
                .by(__.id())\
                .by(__.label())\
                .by(__.valueMap())\
                .by(__.values('embedding').math('cosineSimilarity(' + str(query_embedding) + ')'))\
                .toList()
            
            # Filter by similarity threshold
            similar_nodes = [n for n in similar_nodes if n['similarity'] >= score_threshold]
            
            # Get connected nodes within max_hops
            context = []
            for node in similar_nodes:
                connected = self.g.V(node['id'])\
                    .repeat(__.bothE().otherV())\
                    .times(max_hops)\
                    .dedup()\
                    .project('id', 'label', 'properties')\
                    .by(__.id())\
                    .by(__.label())\
                    .by(__.valueMap())\
                    .toList()
                
                context.append({
                    'primary_node': node,
                    'connected_nodes': connected
                })
            
            return {
                'query': query,
                'query_time': datetime.now().isoformat(),
                'contexts': context,
                'metadata': {
                    'total_nodes': len(similar_nodes),
                    'total_connected': sum(len(c['connected_nodes']) for c in context),
                    'max_similarity': max([n['similarity'] for n in similar_nodes]) if similar_nodes else 0
                }
            }
            
        except Exception as e:
            logger.error(f"Error retrieving graph context: {str(e)}")
            raise

    def close(self):
        """Close the Neptune connection."""
        try:
            if hasattr(self, 'connection'):
                self.connection.close()
        except Exception as e:
            logger.error(f"Error closing Neptune connection: {str(e)}")
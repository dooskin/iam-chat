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
from gremlin_python.structure.io import graphson

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
            # Define core vertex labels
            vertex_labels = ['User', 'Resource', 'Group', 'Role', 'Application']
            
            # Create property indices for better query performance
            for label in vertex_labels:
                try:
                    # Create index on id property
                    self.g.V().hasLabel(label).has('id').limit(1).next()
                    logger.info(f"Verified index exists for {label}:id")
                except Exception:
                    # Neptune automatically creates indices for properties used in queries
                    logger.info(f"Index will be auto-created for {label}:id")
                
                # Initialize a test vertex to ensure label is registered
                test_vertex_id = f"test_{label.lower()}_{int(time.time())}"
                self.g.addV(label)\
                    .property('id', test_vertex_id)\
                    .property('name', f'Test {label}')\
                    .property('lastupdated', int(time.time() * 1000))\
                    .property('firstseen', int(time.time() * 1000))\
                    .next()
                
                # Clean up test vertex
                self.g.V().has('id', test_vertex_id).drop().iterate()
                logger.info(f"Initialized schema for {label}")
            
            # Define relationship types
            rel_types = ["HAS_PERMISSION", "BELONGS_TO", "MANAGES", "OWNS", "ACCESSES"]
            
            # Test and register edge labels
            test_source_id = f"test_source_{int(time.time())}"
            test_target_id = f"test_target_{int(time.time())}"
            
            try:
                # Create test vertices
                source = self.g.addV('User')\
                    .property('id', test_source_id)\
                    .next()
                target = self.g.addV('Resource')\
                    .property('id', test_target_id)\
                    .next()
                
                # Create test edges for each relationship type
                for rel_type in rel_types:
                    self.g.V(source)\
                        .addE(rel_type)\
                        .to(self.g.V(target))\
                        .property('lastupdated', int(time.time() * 1000))\
                        .property('firstseen', int(time.time() * 1000))\
                        .next()
                    logger.info(f"Registered edge label: {rel_type}")
                
            finally:
                # Clean up test vertices
                self.g.V().hasId(test_source_id, test_target_id).drop().iterate()
            
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
            
            # Prepare metadata with Cartography compatibility
            node_metadata = {
                'last_updated': datetime.now().isoformat(),
                'content_length': len(text_content),
                'embedding_model': 'text-embedding-3-small',
                'lastupdated': int(datetime.now().timestamp() * 1000),
                'firstseen': int(datetime.now().timestamp() * 1000)
            }
            if metadata:
                node_metadata.update(metadata)
            
            # Neptune requires array properties to be serialized
            embedding_json = json.dumps(embedding)
            
            retry_count = 0
            max_retries = 3
            last_error = None
            
            while retry_count < max_retries:
                try:
                    # Create or update vertex with proper error handling
                    vertex = self.g.addV(node_type)\
                        .property('id', node_id)\
                        .property('text_content', text_content)\
                        .property('embedding', embedding_json)\
                        .property('vector_dim', len(embedding))\
                        .property('last_updated', node_metadata['last_updated'])\
                        .property('content_length', node_metadata['content_length'])\
                        .property('embedding_model', node_metadata['embedding_model'])\
                        .property('lastupdated', node_metadata['lastupdated'])\
                        .property('firstseen', node_metadata['firstseen'])
                    
                    # Add any additional metadata properties
                    for key, value in node_metadata.items():
                        if key not in ['last_updated', 'content_length', 'embedding_model', 'lastupdated', 'firstseen']:
                            vertex = vertex.property(key, value)
                    
                    # Execute the traversal
                    vertex.next()
                    logger.info(f"Successfully created node {node_id} with embedding")
                    break
                    
                except Exception as e:
                    retry_count += 1
                    last_error = str(e)
                    
                    if retry_count < max_retries:
                        wait_time = min(2 ** retry_count, 30)
                        logger.warning(f"Attempt {retry_count} failed: {last_error}")
                        logger.info(f"Retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                    else:
                        raise Exception(f"Failed to create node after {max_retries} attempts: {last_error}")
            
            logger.info(f"Successfully created embedding for node {node_id} of type {node_type}")
                
        except Exception as e:
            logger.error(f"Error creating node embedding: {str(e)}")
            raise

    def get_graph_context(self, query: str, limit: int = 5, max_hops: int = 2, score_threshold: float = 0.6) -> Dict[str, Any]:
        """Retrieve relevant graph context using similarity search and relationship traversal."""
        try:
            start_time = time.time()
            logger.info(f"Generating embedding for query: {query}")
            
            # Generate query embedding
            query_embedding = self.openai.embeddings.create(
                model="text-embedding-3-small",
                input=query
            ).data[0].embedding
            
            # Convert embedding to JSON for Neptune compatibility
            query_embedding_json = json.dumps(query_embedding)
            
            logger.info("Executing vector similarity search...")
            
            # Find similar nodes using Neptune's vector similarity capabilities
            similar_nodes = self.g.V()\
                .has('embedding')\
                .order()\
                .by(__.coalesce(
                    __.values('embedding').math('neptune#similarity(vector_cosine, ' + query_embedding_json + ')'),
                    __.constant(-1)
                ), Order.desc)\
                .limit(limit)\
                .project('id', 'label', 'properties', 'similarity')\
                .by(__.id())\
                .by(__.label())\
                .by(__.valueMap())\
                .by(__.values('embedding').math('neptune#similarity(vector_cosine, ' + query_embedding_json + ')'))\
                .toList()
            
            logger.info(f"Found {len(similar_nodes)} similar nodes in {time.time() - start_time:.2f} seconds")
            
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
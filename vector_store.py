import os
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from pinecone import Pinecone, ServerlessSpec
from openai import OpenAI

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VectorStore:
    """Vector store implementation using Pinecone serverless for efficient similarity search."""
    
    def __init__(self):
        """Initialize Pinecone client and OpenAI for embeddings."""
        try:
            # Initialize Pinecone with API key
            api_key = os.getenv('PINECONE_API_KEY')
            if not api_key:
                raise ValueError("PINECONE_API_KEY environment variable is required")
                
            self.pc = Pinecone(api_key=api_key)
            
            # Initialize OpenAI client
            self.openai = OpenAI()
            
            # Get or create serverless index
            self.index_name = "graph-rag-index"
            self.dimension = 1536  # OpenAI embedding dimension
            
            # List existing indexes
            indexes = self.pc.list_indexes()
            
            # Create serverless index if it doesn't exist
            if not any(index.name == self.index_name for index in indexes):
                self.pc.create_index(
                    name=self.index_name,
                    dimension=self.dimension,
                    metric="cosine",
                    spec=ServerlessSpec(
                        cloud="aws",
                        region="us-east-1"
                    )
                )
                logger.info(f"Created new serverless index: {self.index_name}")
            
            # Connect to index
            self.index = self.pc.Index(self.index_name)
            logger.info("Vector store initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize vector store: {str(e)}")
            raise
    
    def create_embedding(self, text: str) -> List[float]:
        """Generate embedding vector using OpenAI API."""
        try:
            response = self.openai.embeddings.create(
                model="text-embedding-3-small",
                input=text
            )
            return response.data[0].embedding
        except Exception as e:
            logger.error(f"Failed to create embedding: {str(e)}")
            raise
    
    def store_embedding(
        self,
        node_id: str,
        node_type: str,
        text_content: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Store embedding vector with metadata in Pinecone."""
        try:
            # Generate embedding
            embedding = self.create_embedding(text_content)
            
            # Prepare metadata
            meta = {
                "node_type": node_type,
                "text_content": text_content,
                "last_updated": datetime.now().isoformat(),
                "embedding_model": "text-embedding-3-small"
            }
            if metadata:
                meta.update(metadata)
            
            # Upsert to Pinecone using the latest API
            self.index.upsert(
                vectors=[{
                    "id": node_id,
                    "values": embedding,
                    "metadata": meta
                }]
            )
            logger.info(f"Successfully stored embedding for {node_id} of type {node_type}")
            
        except Exception as e:
            logger.error(f"Failed to store embedding: {str(e)}")
            raise
    
    def search_similar(
        self,
        query: str,
        node_type: Optional[str] = None,
        limit: int = 5,
        score_threshold: float = 0.7
    ) -> List[Dict[str, Any]]:
        """Search for similar vectors in Pinecone."""
        try:
            # Generate query embedding
            query_vector = self.create_embedding(query)
            
            # Prepare filter if node_type is specified
            filter_dict = {"node_type": {"$eq": node_type}} if node_type else None
            
            # Query Pinecone
            results = self.index.query(
                vector=query_vector,
                filter=filter_dict,
                top_k=limit,
                include_metadata=True
            )
            
            # Process and filter results
            processed_results = []
            for match in results['matches']:
                if match['score'] >= score_threshold:
                    processed_results.append({
                        "node_id": match['id'],
                        "similarity": match['score'],
                        "metadata": match['metadata']
                    })
            
            return processed_results
            
        except Exception as e:
            logger.error(f"Failed to search vectors: {str(e)}")
            raise
    
    def batch_search_similar(
        self,
        query: str,
        node_types: Optional[List[str]] = None,
        limit_per_type: int = 3,
        score_threshold: float = 0.7
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Search across multiple node types."""
        try:
            if node_types is None:
                node_types = ["User", "Resource", "Group", "Role", "Application"]
            
            results = {}
            for node_type in node_types:
                try:
                    # Search for each node type
                    type_results = self.search_similar(
                        query=query,
                        node_type=node_type,
                        limit=limit_per_type,
                        score_threshold=score_threshold
                    )
                    
                    if type_results:
                        results[node_type.lower()] = type_results
                        
                except Exception as e:
                    logger.warning(f"Error searching node type {node_type}: {str(e)}")
                    continue
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to batch search vectors: {str(e)}")
            raise

import os
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from qdrant_client import QdrantClient
from qdrant_client.http import models
from openai import OpenAI

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VectorStore:
    """Vector store implementation using Qdrant for efficient similarity search."""
    
    def __init__(self):
        """Initialize Qdrant client and OpenAI for embeddings."""
        try:
            # Initialize Qdrant (in-memory for Replit deployment)
            self.client = QdrantClient(":memory:")
            self.openai = OpenAI()
            
            # Create collections for different node types
            self._init_collections()
            logger.info("Vector store initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize vector store: {str(e)}")
            raise
    
    def _init_collections(self):
        """Initialize collections for different node types."""
        try:
            # Define core collections
            collections = [
                "users", "resources", "groups", "roles", "applications",
                "aws_accounts", "gcp_projects", "azure_subscriptions"
            ]
            
            for collection in collections:
                self.client.recreate_collection(
                    collection_name=collection,
                    vectors_config=models.VectorParams(
                        size=1536,  # OpenAI embedding dimension
                        distance=models.Distance.COSINE
                    )
                )
                logger.info(f"Collection '{collection}' initialized")
                
        except Exception as e:
            logger.error(f"Failed to initialize collections: {str(e)}")
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
        collection: str,
        node_id: str,
        text_content: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Store embedding vector with metadata."""
        try:
            # Generate embedding
            embedding = await self.create_embedding(text_content)
            
            # Prepare payload
            payload = {
                "node_id": node_id,
                "text_content": text_content,
                "last_updated": datetime.now().isoformat(),
                "embedding_model": "text-embedding-3-small"
            }
            if metadata:
                payload.update(metadata)
            
            # Store in Qdrant
            self.client.upsert(
                collection_name=collection,
                points=[
                    models.PointStruct(
                        id=node_id,
                        vector=embedding,
                        payload=payload
                    )
                ]
            )
            logger.info(f"Successfully stored embedding for {node_id} in {collection}")
            
        except Exception as e:
            logger.error(f"Failed to store embedding: {str(e)}")
            raise
    
    def search_similar(
        self,
        collection: str,
        query: str,
        limit: int = 5,
        score_threshold: float = 0.7
    ) -> List[Dict[str, Any]]:
        """Search for similar vectors in the collection."""
        try:
            # Generate query embedding
            query_vector = await self.create_embedding(query)
            
            # Search in Qdrant
            results = self.client.search(
                collection_name=collection,
                query_vector=query_vector,
                limit=limit,
                score_threshold=score_threshold
            )
            
            # Process results
            return [{
                "node_id": hit.id,
                "similarity": hit.score,
                "metadata": hit.payload
            } for hit in results]
            
        except Exception as e:
            logger.error(f"Failed to search vectors: {str(e)}")
            raise
    
    def batch_search_similar(
        self,
        query: str,
        collections: Optional[List[str]] = None,
        limit_per_collection: int = 3,
        score_threshold: float = 0.7
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Search across multiple collections."""
        try:
            if collections is None:
                collections = [
                    "users", "resources", "groups", "roles", "applications"
                ]
            
            results = {}
            # Generate query embedding once for all collections
            query_vector = self.create_embedding(query)
            
            for collection in collections:
                try:
                    # Search in collection
                    search_results = self.client.search(
                        collection_name=collection,
                        query_vector=query_vector,
                        limit=limit_per_collection,
                        score_threshold=score_threshold
                    )
                    
                    # Process results
                    collection_results = [{
                        "node_id": hit.id,
                        "similarity": hit.score,
                        "metadata": hit.payload
                    } for hit in search_results]
                    
                    if collection_results:
                        results[collection] = collection_results
                        
                except Exception as e:
                    logger.warning(f"Error searching collection {collection}: {str(e)}")
                    continue
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to batch search vectors: {str(e)}")
            raise

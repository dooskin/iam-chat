import os
import logging
from datetime import datetime
from cartography_sync import CartographySync
from google.oauth2.credentials import Credentials

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_cartography_sync():
    """Test Cartography synchronization with GCP resources."""
    try:
        logger.info("Starting Cartography sync test...")
        
        # Initialize sync module
        sync = CartographySync()
        
        # Create test credentials (mock for testing)
        test_creds = Credentials(
            token="test_token",
            refresh_token="test_refresh_token",
            token_uri="https://oauth2.googleapis.com/token",
            client_id=os.environ.get('GOOGLE_CLIENT_ID'),
            client_secret=os.environ.get('GOOGLE_CLIENT_SECRET')
        )
        
        # Run sync process
        logger.info("Running GCP resource synchronization...")
        sync.sync_gcp_resources(test_creds)
        
        logger.info("Cartography sync test completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Cartography sync test failed: {str(e)}")
        logger.error("Stack trace:", exc_info=True)
        return False
    finally:
        sync.close()

if __name__ == "__main__":
    test_cartography_sync()

import os
import json
import hashlib
import pickle
from datetime import datetime
from typing import Any, Dict, Optional

class ModelVersionManager:
    """
    Manages versioning, storage, and retrieval of machine learning models
    """
    def __init__(self, base_path: str = 'model_versions'):
        """
        Initialize ModelVersionManager with a base storage path
        
        :param base_path: Directory to store model versions
        """
        self.base_path = base_path
        os.makedirs(base_path, exist_ok=True)
    
    def _generate_model_hash(self, model: Any) -> str:
        """
        Generate a unique hash for a model based on its serialized state
        
        :param model: Machine learning model to hash
        :return: Unique hash string
        """
        model_bytes = pickle.dumps(model)
        return hashlib.sha256(model_bytes).hexdigest()
    
    def save_model(self, model: Any, metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Save a model version with optional metadata
        
        :param model: Machine learning model to save
        :param metadata: Additional metadata about the model
        :return: Version identifier
        """
        # Generate unique identifiers
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_hash = self._generate_model_hash(model)
        version_id = f"{timestamp}_{model_hash[:8]}"
        
        # Prepare version metadata
        version_metadata = {
            'timestamp': timestamp,
            'hash': model_hash,
            'metadata': metadata or {}
        }
        
        # Create version directory
        version_dir = os.path.join(self.base_path, version_id)
        os.makedirs(version_dir, exist_ok=True)
        
        # Save model
        model_path = os.path.join(version_dir, 'model.pkl')
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        
        # Save metadata
        metadata_path = os.path.join(version_dir, 'metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(version_metadata, f, indent=2)
        
        return version_id
    
    def load_model(self, version_id: str) -> Any:
        """
        Load a specific model version
        
        :param version_id: Identifier of the model version
        :return: Loaded model
        """
        version_dir = os.path.join(self.base_path, version_id)
        model_path = os.path.join(version_dir, 'model.pkl')
        
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model version {version_id} not found")
        
        with open(model_path, 'rb') as f:
            return pickle.load(f)
    
    def list_versions(self) -> Dict[str, Dict[str, Any]]:
        """
        List all available model versions
        
        :return: Dictionary of version metadata
        """
        versions = {}
        for version_id in os.listdir(self.base_path):
            metadata_path = os.path.join(self.base_path, version_id, 'metadata.json')
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    versions[version_id] = json.load(f)
        return versions
    
    def delete_version(self, version_id: str) -> None:
        """
        Delete a specific model version
        
        :param version_id: Identifier of the model version to delete
        """
        import shutil
        version_dir = os.path.join(self.base_path, version_id)
        
        if os.path.exists(version_dir):
            shutil.rmtree(version_dir)

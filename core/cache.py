import json
import os
import time
from typing import Dict, Optional
import logging

CACHE_DIR = "cache"
CACHE_DURATION = 3600  # 1 hour

class ScanCache:
    def __init__(self):
        os.makedirs(CACHE_DIR, exist_ok=True)
        self.cache_file = os.path.join(CACHE_DIR, "scan_cache.json")
        
    def _load_cache(self) -> Dict:
        """Load the cache from file."""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logging.error(f"Error loading cache: {str(e)}")
            return {}

    def _save_cache(self, cache_data: Dict) -> None:
        """Save the cache to file."""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f)
        except Exception as e:
            logging.error(f"Error saving cache: {str(e)}")

    def get_results(self, target: str) -> Optional[Dict]:
        """Get cached scan results for a target."""
        cache = self._load_cache()
        if target in cache:
            result = cache[target]
            if time.time() - result["timestamp"] < CACHE_DURATION:
                return result["data"]
        return None

    def store_results(self, target: str, results: Dict) -> None:
        """Store scan results in cache."""
        cache = self._load_cache()
        cache[target] = {
            "timestamp": time.time(),
            "data": results
        }
        self._save_cache(cache)

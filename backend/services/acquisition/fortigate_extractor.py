import os
import time
import json
import requests
import logging
from datetime import datetime
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("FortiGateExtractor")

class FortiGateExtractor:
    def __init__(self):
        load_dotenv()
        self.host = os.getenv("FGT_HOST")
        self.token = os.getenv("FGT_TOKEN")
        self.vdom = os.getenv("FGT_VDOM", "root")
        self.debug_mode = os.getenv("DEBUG_MODE", "False").lower() in ("true", "1", "yes")
        self.output_dir = os.getenv("OUTPUT_DIR", "../../output")
        self.device_id = "FGT-1"
        self.firmware_version = "7.0.5" # Hardcoded for lab, typically fetched via system/status API

        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json"
        }
        
        self.base_url = f"https://{self.host}/api/v2/cmdb"
        # Disable SSL warnings for self-signed lab certificates
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    def _make_request(self, endpoint, params=None):
        if not params:
            params = {}
        params["vdom"] = self.vdom
        url = f"{self.base_url}{endpoint}"
        
        try:
            response = requests.get(url, headers=self.headers, params=params, verify=False, timeout=10)
            response.raise_for_status()
            return response.json().get('results', [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch {endpoint}: {e}")
            return None

    def get_policies(self):
        logger.info("Fetching FortiGate Policies...")
        return self._make_request("/firewall/policy")

    def get_addresses(self):
        logger.info("Fetching FortiGate Addresses...")
        return self._make_request("/firewall/address")

    def get_services(self):
        logger.info("Fetching FortiGate Services...")
        # Custom services
        custom = self._make_request("/firewall.service/custom") or []
        # Group services
        groups = self._make_request("/firewall.service/group") or []
        return custom + groups

    def get_interfaces(self):
        logger.info("Fetching FortiGate Interfaces...")
        return self._make_request("/system/interface")

    def format_output(self, data_type, raw_data):
        return {
            "metadata": {
                "device_id": self.device_id,
                "vendor": "fortinet",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "firmware_version": self.firmware_version,
                "data_type": data_type
            },
            "data": raw_data
        }

    def save_to_file(self, filename, data):
        device_dir = os.path.join(self.output_dir, "fortigate", self.device_id)
        os.makedirs(device_dir, exist_ok=True)
        filepath = os.path.join(device_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved {filename} to {filepath}")

    def run(self, incremental=False):
        """
        Runs the extraction process.
        If incremental=True, we would pass a timestamp to the API to only fetch changes.
        FortiGate doesn't natively support incremental pulls on CMDB API without revision tracking,
        but we can simulate it by storing state or doing full pulls and letting parser handle differences.
        For this implementation, we pull full and wrap in the standardized structure.
        """
        logger.info(f"Starting FortiGate Extraction (Incremental: {incremental})")
        
        policies = self.get_policies()
        addresses = self.get_addresses()
        services = self.get_services()
        
        if policies is None or addresses is None:
            logger.error("Extraction failed due to API errors. Aborting this cycle.")
            return None
            
        policies_output = self.format_output("policies", policies)
        objects_output = self.format_output("objects", {
            "addresses": addresses,
            "services": services
        })

        if self.debug_mode:
            logger.info("Debug mode enabled. Saving output to files.")
            self.save_to_file("policies.json", policies_output)
            self.save_to_file("objects.json", objects_output)
            
        logger.info("Extraction complete. Returning data to parsing layer.")
        return {
            "policies": policies_output,
            "objects": objects_output
        }

if __name__ == "__main__":
    extractor = FortiGateExtractor()
    extractor.run()

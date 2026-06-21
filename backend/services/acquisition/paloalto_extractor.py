import os
import time
import requests
import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("PaloAltoExtractor")

class PaloAltoExtractor:
    def __init__(self):
        load_dotenv()
        self.host = os.getenv("PA_HOST")
        self.api_key = os.getenv("PA_API_KEY")
        self.vsys = os.getenv("PA_VSYS", "vsys1")
        self.debug_mode = os.getenv("DEBUG_MODE", "False").lower() in ("true", "1", "yes")
        self.output_dir = os.getenv("OUTPUT_DIR", "../../output")
        self.device_id = "PA-1"
        self.firmware_version = "11.1.6"

        self.base_url = f"https://{self.host}/api/"
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    def _make_request(self, params):
        if not self.api_key:
            logger.error("No API key configured for Palo Alto.")
            return None
            
        params["key"] = self.api_key
        
        try:
            response = requests.get(self.base_url, params=params, verify=False, timeout=15)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch data from Palo Alto API: {e}")
            return None

    def get_policies(self):
        logger.info("Fetching Palo Alto Policies...")
        params = {
            "type": "config",
            "action": "show",
            "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/rulebase/security"
        }
        return self._make_request(params)

    def get_objects(self):
        logger.info("Fetching Palo Alto Objects...")
        # Addresses
        params_addr = {
            "type": "config",
            "action": "show",
            "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/address"
        }
        addresses = self._make_request(params_addr)
        
        # Services
        params_srv = {
            "type": "config",
            "action": "show",
            "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/service"
        }
        services = self._make_request(params_srv)
        
        return {"addresses": addresses, "services": services}

    def format_output_xml(self, raw_xml):
        """ Wraps raw XML output in standard metadata """
        if raw_xml is None:
            return None
        
        # Simple string manipulation for XML metadata wrapper
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        wrapped = f"""<response>
  <metadata>
    <device_id>{self.device_id}</device_id>
    <vendor>paloalto</vendor>
    <timestamp>{timestamp}</timestamp>
    <firmware_version>{self.firmware_version}</firmware_version>
  </metadata>
  <data>
    {raw_xml}
  </data>
</response>"""
        return wrapped

    def save_to_file(self, filename, data):
        if not data:
            return
            
        device_dir = os.path.join(self.output_dir, "paloalto", self.device_id)
        os.makedirs(device_dir, exist_ok=True)
        filepath = os.path.join(device_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(data)
        logger.info(f"Saved {filename} to {filepath}")

    def run(self, incremental=False):
        """
        Runs the extraction process.
        """
        logger.info(f"Starting Palo Alto Extraction (Incremental: {incremental})")
        
        policies_xml = self.get_policies()
        objects_xml_dict = self.get_objects()
        
        if policies_xml is None or objects_xml_dict["addresses"] is None:
            logger.error("Extraction failed due to API errors. Aborting this cycle.")
            return None
            
        policies_output = self.format_output_xml(policies_xml)
        
        # Combine addresses and services for objects output
        combined_objects_xml = f"<objects>\n{objects_xml_dict['addresses']}\n{objects_xml_dict['services']}\n</objects>"
        objects_output = self.format_output_xml(combined_objects_xml)

        if self.debug_mode:
            logger.info("Debug mode enabled. Saving output to files.")
            self.save_to_file("policies.xml", policies_output)
            self.save_to_file("objects.xml", objects_output)
            
        logger.info("Extraction complete. Returning data to parsing layer.")
        return {
            "policies": policies_output,
            "objects": objects_output
        }

if __name__ == "__main__":
    extractor = PaloAltoExtractor()
    extractor.run()

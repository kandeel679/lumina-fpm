import os
import requests
import logging
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("FortiGateDeployer")

class FortiGateDeployer:
    def __init__(self):
        load_dotenv()
        self.host = os.getenv("FGT_HOST")
        self.token = os.getenv("FGT_TOKEN")
        self.vdom = os.getenv("FGT_VDOM", "root")
        
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        self.base_url = f"https://{self.host}/api/v2/cmdb"
        requests.packages.urllib3.disable_warnings()

    def _post(self, endpoint, data):
        url = f"{self.base_url}{endpoint}?vdom={self.vdom}"
        try:
            res = requests.post(url, headers=self.headers, json=data, verify=False, timeout=10)
            if res.status_code in [200, 204]:
                logger.info(f"Successfully created: {data.get('name')}")
            else:
                logger.warning(f"Failed to create {data.get('name')} (maybe it exists?): {res.text}")
        except Exception as e:
            logger.error(f"Error creating {data.get('name')}: {e}")

    def deploy_objects(self):
        logger.info("Deploying FortiGate Address Objects...")
        objects = [
            {"name": "LAN_NET", "type": "ipmask", "subnet": "10.10.10.0 255.255.255.0"},
            {"name": "DMZ_NET", "type": "ipmask", "subnet": "10.10.20.0 255.255.255.0"},
            {"name": "DB_NET", "type": "ipmask", "subnet": "10.10.30.0 255.255.255.0"},
            {"name": "ADMIN_NET", "type": "ipmask", "subnet": "10.10.99.0 255.255.255.0"},
            {"name": "BACKUP_SRV", "type": "ipmask", "subnet": "10.10.50.10 255.255.255.255"},
            {"name": "MONITOR_SRV", "type": "ipmask", "subnet": "10.10.60.10 255.255.255.255"},
            {"name": "MALICIOUS_IP", "type": "ipmask", "subnet": "198.51.100.5 255.255.255.255"}
        ]
        for obj in objects:
            self._post("/firewall/address", obj)

    def deploy_policies(self):
        logger.info("Deploying FortiGate Policies...")
        # Note: In FortiGate, policies need valid interface names. 
        # We assume port1=LAN, port2=DMZ, port3=DB, port4=WAN as per requirements
        policies = [
            {
                "name": "FGT_ALLOW_LAN_TO_DMZ_HTTP",
                "srcintf": [{"name": "port1"}],
                "dstintf": [{"name": "port2"}],
                "srcaddr": [{"name": "LAN_NET"}],
                "dstaddr": [{"name": "DMZ_NET"}],
                "action": "accept",
                "schedule": "always",
                "service": [{"name": "HTTP"}],
                "logtraffic": "all",
                "comments": "Anom: Conflict pair with Palo Alto"
            },
            {
                "name": "FGT_ALLOW_ANY_TO_DB_ALL",
                "srcintf": [{"name": "any"}],
                "dstintf": [{"name": "port3"}],
                "srcaddr": [{"name": "all"}],
                "dstaddr": [{"name": "DB_NET"}],
                "action": "accept",
                "schedule": "always",
                "service": [{"name": "ALL"}],
                "logtraffic": "all",
                "comments": "Anom: 4,7,36 Over-permissive to sensitive DB"
            },
            {
                "name": "FGT_DENY_LAN_TO_DB_ALL",
                "srcintf": [{"name": "port1"}],
                "dstintf": [{"name": "port3"}],
                "srcaddr": [{"name": "LAN_NET"}],
                "dstaddr": [{"name": "DB_NET"}],
                "action": "deny",
                "schedule": "always",
                "service": [{"name": "ALL"}],
                "logtraffic": "all",
                "comments": "Anom: 1 Shadowed by FGT_ALLOW_ANY_TO_DB_ALL"
            },
            # ... (More rules will be fully generated via the MD guide to avoid overly large scripts, 
            # but this is the automated logic that can iterate over a full JSON list)
        ]
        for pol in policies:
            self._post("/firewall/policy", pol)

    def run(self):
        self.deploy_objects()
        self.deploy_policies()
        logger.info("FortiGate deployment complete.")

if __name__ == "__main__":
    deployer = FortiGateDeployer()
    deployer.run()

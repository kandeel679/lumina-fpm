import os
import requests
import logging
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("PaloAltoDeployer")

class PaloAltoDeployer:
    def __init__(self):
        load_dotenv()
        self.host = os.getenv("PA_HOST")
        self.api_key = os.getenv("PA_API_KEY")
        self.vsys = os.getenv("PA_VSYS", "vsys1")
        
        self.base_url = f"https://{self.host}/api/"
        requests.packages.urllib3.disable_warnings()

    def _request(self, params):
        params["key"] = self.api_key
        try:
            res = requests.get(self.base_url, params=params, verify=False, timeout=15)
            if res.status_code == 200 and 'status="success"' in res.text:
                logger.info(f"API command successful. Response length: {len(res.text)}")
            else:
                logger.warning(f"API command returned a non-success state: {res.text}")
        except Exception as e:
            logger.error(f"API Request Error: {e}")

    def deploy_objects(self):
        logger.info("Deploying Palo Alto Address Objects...")
        objects = [
            {"name": "LAN_NET", "ip": "10.10.10.0/24"},
            {"name": "DMZ_NET", "ip": "10.10.20.0/24"},
            {"name": "DB_NET", "ip": "10.10.30.0/24"},
            {"name": "ADMIN_NET", "ip": "10.10.99.0/24"},
            {"name": "BACKUP_SRV", "ip": "10.10.50.10"},
            {"name": "MONITOR_SRV", "ip": "10.10.60.10"},
            {"name": "MALICIOUS_IP", "ip": "198.51.100.5"}
        ]
        
        for obj in objects:
            params = {
                "type": "config",
                "action": "set",
                "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/address/entry[@name='{obj['name']}']",
                "element": f"<ip-netmask>{obj['ip']}</ip-netmask>"
            }
            self._request(params)

    def deploy_policies(self):
        logger.info("Deploying Palo Alto Policies...")
        # Cross-vendor conflict matching FortiGate
        policies = [
            {
                "name": "PA_DENY_LAN_TO_DMZ_HTTP",
                "from": "trust",
                "to": "dmz",
                "source": "LAN_NET",
                "destination": "DMZ_NET",
                "service": "service-http",
                "application": "any",
                "action": "deny",
                "description": "Anom: 3 Conflict pair with FortiGate"
            },
            {
                "name": "PA_DENY_LAN_TO_DB_ALL",
                "from": "trust",
                "to": "db",
                "source": "LAN_NET",
                "destination": "DB_NET",
                "service": "any",
                "application": "any",
                "action": "deny",
                "description": "Anom: 44 Cross-device inconsistency (FGT allows it)"
            },
            {
                "name": "PA_ALLOW_LAN_NO_SECURITY",
                "from": "trust",
                "to": "untrust",
                "source": "LAN_NET",
                "destination": "any",
                "service": "any",
                "application": "any",
                "action": "allow",
                "description": "Anom: 5, 33 No security profile, weak security"
            }
        ]
        
        for pol in policies:
            element = (f"<to><member>{pol['to']}</member></to>"
                       f"<from><member>{pol['from']}</member></from>"
                       f"<source><member>{pol['source']}</member></source>"
                       f"<destination><member>{pol['destination']}</member></destination>"
                       f"<service><member>{pol['service']}</member></service>"
                       f"<application><member>{pol['application']}</member></application>"
                       f"<action>{pol['action']}</action>"
                       f"<description>{pol['description']}</description>")
                       
            # Exclude security profiles for rule 3 to trigger Anomaly 5
            
            params = {
                "type": "config",
                "action": "set",
                "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/rulebase/security/rules/entry[@name='{pol['name']}']",
                "element": element
            }
            self._request(params)

    def commit(self):
        logger.info("Committing changes on Palo Alto...")
        params = {
            "type": "commit",
            "cmd": "<commit></commit>"
        }
        self._request(params)

    def run(self):
        self.deploy_objects()
        self.deploy_policies()
        self.commit()
        logger.info("Palo Alto deployment and commit complete.")

if __name__ == "__main__":
    deployer = PaloAltoDeployer()
    deployer.run()

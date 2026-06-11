"""Full-cycle test augmentation: make the seeded NovaTech tenant look like a
real, fully-connected enterprise so EVERY pipeline stage has data to chew on.

Adds (idempotently, on top of seed_data.py):
  - fqdn/domain NetworkObjects (org domains) -> unlocks credential query
    generation AND the Ransomware.live leak-site check (both skipped today
    because the base seed has no domains).
  - a public ip-netmask object (NAT'd web frontend) -> exercises IOC<->rule
    correlation and exposes how ip-netmask values leak into org_domains.
  - RuleObjectMappings tying the new objects to real rules on real devices ->
    lets the correlator upgrade an IOC hit all the way to rules/devices.

Run:  docker exec lumina-fpm-api-1 python seed_test_cycle.py
"""
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models.models import FirewallDevice, NetworkObject, PolicyRule, RuleObjectMapping

engine = create_engine(os.environ["DATABASE_URL"])
db = sessionmaker(bind=engine)()

# (name, type, value) — novatech.com deliberately resembles a REAL Akira
# leak-site victim ("Novatech Engineering Consultants") so the possible-match
# honesty path is exercised by live data.
OBJECTS = [
    ("ORG-DOMAIN-PRIMARY", "fqdn", "novatech.com"),
    ("ORG-VPN-PORTAL", "fqdn", "vpn.novatech.com"),
    ("ORG-WEBMAIL", "fqdn", "mail.novatech.com"),
    ("ORG-CUSTOMER-PORTAL", "fqdn", "portal.novatech.com"),
    ("NAT-PUBLIC-WEB", "ip-netmask", "203.0.113.50"),
]

created_objs = []
for name, typ, value in OBJECTS:
    obj = db.query(NetworkObject).filter_by(value=value).first()
    if obj is None:
        obj = NetworkObject(name=name, type=typ, value=value)
        db.add(obj)
        db.flush()
        created_objs.append(value)
    # map each object to the first active rule of every device so a domain/IP
    # IOC hit correlates to concrete rules on concrete firewalls
    for dev in db.query(FirewallDevice).all():
        rule = (db.query(PolicyRule)
                .filter_by(device_id=dev.device_id, is_active=True)
                .order_by(PolicyRule.rule_order).first())
        if rule is None:
            continue
        exists = db.query(RuleObjectMapping).filter_by(
            rule_id=rule.rule_id, object_id=obj.object_id,
            mapping_type="destination").first()
        if exists is None:
            db.add(RuleObjectMapping(rule_id=rule.rule_id, object_id=obj.object_id,
                                     mapping_type="destination", direction="both"))

db.commit()
print(f"Created {len(created_objs)} new network objects: {created_objs}")
print("Total fqdn/domain objects:",
      db.query(NetworkObject).filter(NetworkObject.type.in_(["fqdn", "domain"])).count())
print("Total rule-object mappings:", db.query(RuleObjectMapping).count())
db.close()

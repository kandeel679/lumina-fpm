import sys
import os
import logging
import argparse
from pathlib import Path

# Add backend directory to path so imports work
backend_dir = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(backend_dir))

# Try to load .env from the root directory
try:
    from dotenv import load_dotenv
    root_dir = backend_dir.parent
    env_path = root_dir / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass

from models.models import get_db
from services.lumina_threat_intel.orchestrator import run_scan
from services.lumina_threat_intel.schemas import ThreatCategory

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("intel_test_ground")

def main():
    parser = argparse.ArgumentParser(description="Lumina Threat Intel Testing Ground")
    parser.add_argument("--mock", action="store_true", help="Bypass LLM and Tor scraper (Not fully implemented yet, but sets up the flag)")
    args = parser.parse_args()

    logger.info("Initializing Threat Intel Testing Ground...")
    if args.mock:
        logger.warning("MOCK MODE ENABLED. (Note: Full mock bypass requires modifying orchestrator.py. For now, this just sets a flag.)")
        os.environ["LTI_MOCK_MODE"] = "1"
    
    SessionLocal = get_db()
    db = SessionLocal()
    
    try:
        # Example options for testing
        categories = [
            ThreatCategory.EXPLOIT.value,
            ThreatCategory.CREDENTIAL.value,
            # ThreatCategory.C2.value,
            # ThreatCategory.RANSOMWARE.value,
            # ThreatCategory.IAB.value,
        ]
        
        logger.info(f"Triggering run_scan for categories: {categories}")
        
        # Override the LTI_LLM_PROVIDER to ensure we use a cheaper or specific model if needed
        # os.environ["LTI_LLM_PROVIDER"] = "gemini"
        
        # Execute the scan
        report = run_scan(
            db=db,
            trigger_type="manual",
            admin_id=1,  # Mock admin
            requested_categories=categories
        )
        
        logger.info("=" * 64)
        logger.info("SCAN COMPLETE — Report ID: %s", report.id)
        logger.info("Status: %s | Duration: %ss", report.status, report.scan_duration_seconds)
        logger.info("Model ACTUALLY used: %s", report.llm_model_name)
        logger.info("Queries: %s | Onion pages scraped: %s",
                    report.queries_generated_count, report.onion_pages_scraped_count)
        logger.info("CLEAN (no medium+ relevance finding): %s", report.clean)
        logger.info("COVERAGE NOTE: %s", report.coverage_note)
        logger.info("STATS: %s", report.stats)
        logger.info("NARRATIVE:\n%s", report.narrative_summary)
        logger.info("=" * 64)
        
    except Exception as e:
        logger.error(f"Test ground failed: {e}")
    finally:
        db.close()
        logger.info("Database connection closed.")

if __name__ == "__main__":
    main()

from fastapi import FastAPI
from pydantic import BaseModel
import os

from scrape import scrape_multiple
from search import get_search_results
from llm import get_llm, refine_query, filter_results, generate_summary

app = FastAPI()

class ThreatQuery(BaseModel):
    query: str

def run_dark_web_investigation(query: str):
    # Retrieve model from environment or default to gpt4o
    model_name = os.getenv("ROBIN_MODEL", "gpt4o")
    llm = get_llm(model_name)
    
    refined = refine_query(llm, query)
    
    threads = 4
    results = get_search_results(refined, max_workers=threads)
    if len(results) > 50:
         results = results[:50]
        
    filtered = filter_results(llm, refined, results)
    if len(filtered) > 10:
         filtered = filtered[:10]
        
    scraped = scrape_multiple(filtered, max_workers=threads)
    
    summary = generate_summary(
         llm, query, scraped,
         preset="threat_intel",
         custom_instructions=""
    )
    
    return {
         "refined_query": refined,
         "sources": filtered,
         "summary": summary
    }

@app.post("/api/v1/hunt")
def trigger_hunt(payload: ThreatQuery):
    try:
         report = run_dark_web_investigation(payload.query)
         return {"status": "success", "data": report}
    except Exception as e:
         return {"status": "error", "message": str(e)}

"""
Dataset Exporter Module - Milestone 3
Separates logic for formatting and processing exporting HTTP payloads.
"""
import csv
import io
import json

def format_csv(rows: list[dict]) -> str:
    """Format abstract rows into a CSV string."""
    if not rows:
        return ""
    
    output = io.StringIO()
    # Flatten nested JSON
    for row in rows:
        if "headers" in row and isinstance(row["headers"], dict):
            row["headers"] = json.dumps(row["headers"])
        if "reputation_tags" in row and isinstance(row["reputation_tags"], list):
            row["reputation_tags"] = json.dumps(row["reputation_tags"])
            
    writer = csv.DictWriter(output, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()

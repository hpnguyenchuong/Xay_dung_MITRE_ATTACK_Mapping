import sqlite3
import json

conn = sqlite3.connect('logs/soc_artifacts.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("--- EVIDENCE CHAIN ---")
try:
    cursor.execute('''SELECT id, finding as artifact, behavior, mapping_reason as rule, enterprise_tech_id as technique, confidence, ics_tech_id as ics_translation, source as operational_effect FROM re_findings WHERE drone_id=? OR drone_id='GLOBAL' OR drone_id='ALL_DRONES' ORDER BY id DESC LIMIT 20''', ('DRONE-505',))
    rows = cursor.fetchall()
    print('evidence_chain count:', len(rows))
    for r in rows:
        try:
            cmd = f'{{"cmd": "{r["artifact"]}"}}' if "DF_" not in r["artifact"] else f'{{"mutex": "{r["artifact"]}"}}'
            print(f"Row {r['id']} OK: {cmd}")
        except Exception as e:
            print(f"Row {r['id']} ERROR:", e)
except Exception as e:
    print('ERROR evidence_chain:', e)

print("--- RE FINDINGS ---")
try:
    cursor.execute('''SELECT artifact_address as offset, finding as artifact, artifact_type, source as re_source, validation_level, behavior, mapping_reason as reason, enterprise_tech_id as selected_technique, rejected_candidates, confidence, confidence_breakdown, campaign_stage FROM re_findings WHERE drone_id=? OR drone_id='GLOBAL' OR drone_id='ALL_DRONES' ORDER BY id DESC LIMIT 50''', ('DRONE-505',))
    rows = cursor.fetchall()
    print('re_findings count:', len(rows))
    for row in rows:
        r = dict(row)
        try:
            r["breakdown"] = json.loads(r["confidence_breakdown"]) if r["confidence_breakdown"] else {}
        except Exception as e:
            print("Breakdown JSON error:", e)
            r["breakdown"] = {}
        
        try:
            strength = r["breakdown"].get("evidence_strength", 70) if r["breakdown"] else 70
        except Exception as e:
            print("evidence_strength error:", e)
            
except Exception as e:
    print('ERROR re_findings:', e)

import requests
# Mock VT API script
def check_vt(hash_val):
    print(f"Checking VT for {hash_val}...")
    return {"positives": 15, "total": 70}

import requests
from typing import List, Dict

def get_patient_observations(base_url: str, patient_id: str, code: str) -> List[Dict]:
    # minimal FHIR fetch (BP panel 55284-4)
    url = f"{base_url}/Observation"
    params = {"patient": patient_id, "code": code, "_count": 10, "_sort": "-date"}
    r = requests.get(url, params=params, timeout=10)
    r.raise_for_status()
    data = r.json()
    bundle = data.get("entry", [])
    obs_list = []
    for ent in bundle:
        res = ent.get("resource", {})
        date = res.get("effectiveDateTime") or res.get("issued") or "unknown-date"
        comp = {}
        for c in res.get("component", []):
            coding = (c.get("code", {}).get("coding") or [{}])[0]
            disp = coding.get("display", "")
            val = c.get("valueQuantity", {}).get("value")
            if disp and val is not None:
                comp[disp] = val
        obs_list.append({"date": date, "value": comp})
    return obs_list

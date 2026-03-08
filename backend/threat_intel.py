import os
import sys
import time
import urllib.parse
import requests
import asyncio

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODULES_DIR = os.path.join(PROJECT_ROOT, "Modules")
for _path in (PROJECT_ROOT, MODULES_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from wise_config import CONFIG


OPENCTI_URL = CONFIG["threat_intel"]["opencti_url"]
VT_POST_TO_GET_DELAY = CONFIG["threat_intel"]["vt_post_to_get_delay"]
REQUEST_TIMEOUT = CONFIG["threat_intel"]["request_timeout"]


def _virustotal_api_key():
    return os.environ.get("VIRUSTOTAL_API_KEY", "")


def _opencti_api_key():
    return os.environ.get("OPENCTI_API_KEY", "")


def _safe_get(d, *keys, default=None):
    """Drill into a nested dict safely."""
    for key in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(key, default)
    return d


def query_virustotal(url):
    """
    POST the URL to VirusTotal to trigger an analysis, wait for the analysis
    to complete, then GET the results.

    Returns a dict with keys:
        success (bool), analysis_id, stats, verdict, error
    """
    api_key = _virustotal_api_key()
    headers = {"x-apikey": api_key, "accept": "application/json"}
    result = {
        "success": False,
        "analysis_id": None,
        "stats": {},
        "verdict": "unknown",
        "error": None,
    }

    if not api_key:
        result["error"] = "VirusTotal API key not configured"
        return result

    try:
        post_resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={**headers,
                     "content-type": "application/x-www-form-urlencoded"},
            data=f"url={urllib.parse.quote(url, safe='')}",
            timeout=REQUEST_TIMEOUT,
        )
        post_resp.raise_for_status()
        post_data = post_resp.json()
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
        return result
    except requests.exceptions.HTTPError as exc:
        result["error"] = f"VirusTotal POST HTTP error: {exc}"
        return result
    except Exception as exc:
        result["error"] = f"VirusTotal POST unexpected error: {exc}"
        return result

    analysis_id = _safe_get(post_data, "data", "id")
    result["analysis_id"] = analysis_id

    print(f"  [VT] Analysis submitted (id={analysis_id}). "
          f"Waiting {VT_POST_TO_GET_DELAY}s for analysis to complete …")
    time.sleep(VT_POST_TO_GET_DELAY)

    try:
        get_resp = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        get_resp.raise_for_status()
        get_data = get_resp.json()
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
        return result
    except requests.exceptions.HTTPError as exc:
        result["error"] = f"VirusTotal GET HTTP error: {exc}"
        return result
    except Exception as exc:
        result["error"] = f"VirusTotal GET unexpected error: {exc}"
        return result

    stats = _safe_get(get_data, "data", "attributes", "stats", default={})
    result["stats"] = stats
    result["success"] = True

    malicious = stats.get("malicious",  0)
    suspicious = stats.get("suspicious", 0)

    if malicious > 0:
        result["verdict"] = "malicious"
    elif suspicious > 0:
        result["verdict"] = "suspicious"
    else:
        result["verdict"] = "clean"

    return result


def query_otx(url):
    """
    Query AlienVault OTX for general indicator information about the URL.

    Returns a dict with keys:
        success (bool), pulse_count, verdict, error
    """
    encoded_url = urllib.parse.quote(url, safe="")
    endpoint = f"https://otx.alienvault.com/api/v1/indicators/url/{encoded_url}/general"
    headers = {"Accept": "application/json"}

    result = {
        "success":     False,
        "pulse_count": 0,
        "verdict":     "unknown",
        "error":       None,
    }

    try:
        resp = requests.get(endpoint, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
        return result
    except requests.exceptions.HTTPError as exc:
        result["error"] = f"OTX HTTP error: {exc}"
        return result
    except Exception as exc:
        result["error"] = f"OTX unexpected error: {exc}"
        return result

    pulse_count = _safe_get(data, "pulse_info", "count", default=0)
    result["pulse_count"] = pulse_count
    result["success"] = True
    result["verdict"] = "malicious" if pulse_count > 0 else "clean"

    return result


def query_opencti(url):
    """
    Query OpenCTI GraphQL for active indicators on the URL.

    Returns a dict with keys:
        success (bool), observable_found, indicator_count, indicators, verdict, error
    """
    result = {
        "success":          False,
        "observable_found": False,
        "indicator_count":  0,
        "indicators":       [],
        "verdict":          "unknown",
        "error":            None,
    }

    api_key = _opencti_api_key()
    if not api_key:
        result["error"] = "OpenCTI API key not configured"
        return result

    safe_url = url.replace("\\", "\\\\").replace('"', '\\"')

    graphql_query = f"""
    {{
      stixCyberObservables(
        types: ["Url"]
        filters: {{
          mode: and
          filters: [{{ key: "value", values: ["{safe_url}"], operator: eq, mode: or }}]
          filterGroups: []
        }}
        first: 1
      ) {{
        edges {{
          node {{
            id
            observable_value
            ... on Url {{
              value
            }}
            indicators {{
              edges {{
                node {{
                  id
                  name
                  confidence
                  revoked
                  valid_until
                  pattern
                }}
              }}
            }}
          }}
        }}
      }}
    }}
    """

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }
    payload = {"query": graphql_query}

    try:
        resp = requests.post(
            OPENCTI_URL,
            headers=headers,
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
        return result
    except requests.exceptions.HTTPError as exc:
        if "Bad Request for url" in str(exc):
            result["error"] = f"OpenCTI HTTP error: {exc} — Check if the URL is valid and properly escaped."
        else:
            result["error"] = f"OpenCTI HTTP error: {exc} — {exc.response.text}"
        return result
    except Exception as exc:
        result["error"] = f"OpenCTI unexpected error: {exc}"
        return result

    if "errors" in data:
        messages = [e.get("message", "unknown") for e in data["errors"]]
        result["error"] = f"OpenCTI GraphQL errors: {'; '.join(messages)}"
        return result

    result["success"] = True

    edges = _safe_get(data, "data", "stixCyberObservables",
                      "edges", default=[])

    if not edges:
        result["observable_found"] = False
        result["verdict"] = "clean"
        return result

    result["observable_found"] = True

    indicator_edges = _safe_get(
        edges[0], "node", "indicators", "edges", default=[]
    )
    active_indicators = [
        e["node"] for e in indicator_edges
        if not e.get("node", {}).get("revoked", False)
    ]

    result["indicator_count"] = len(active_indicators)
    result["indicators"] = [
        {
            "id":          ind.get("id"),
            "name":        ind.get("name"),
            "confidence":  ind.get("confidence"),
            "valid_until": ind.get("valid_until"),
            "pattern":     ind.get("pattern"),
        }
        for ind in active_indicators
    ]

    result["verdict"] = "malicious" if active_indicators else "suspicious"
    return result


async def query_scanners(url):
    """
    Query all scanners and aggregate their results.

    Returns a dict with keys:
        virustotal, otx, opencti
    """

    vt_result, otx_result, opencti_result = await asyncio.gather(
        asyncio.to_thread(query_virustotal, url),
        asyncio.to_thread(query_otx, url),
        asyncio.to_thread(query_opencti, url),
    )

    return {
        "virustotal": vt_result,
        "otx": otx_result,
        "opencti": opencti_result,
    }

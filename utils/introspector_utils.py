import logging
import random
import time
from typing import Any, Optional
from urllib.parse import urlencode
import requests
import json

logger = logging.getLogger(__name__)

TIMEOUT = 45
MAX_RETRY = 5
INTROSPECTOR_ENDPOINT = 'https://introspector.oss-fuzz.com/api'

def _construct_url(api: str, params: dict[str, Any]) -> str:
	"""Constructs an encoded url for the |api| with |params|."""
	return api + '?' + urlencode(params)


def query_introspector(api: str, params: dict[str, Any]) -> Optional[requests.Response]:
	"""Queries FuzzIntrospector API and returns the json payload,
	returns an empty dict if unable to get data."""
	for attempt_num in range(1, MAX_RETRY + 1):
		try:
			resp = requests.get(api, params, timeout=TIMEOUT)
			if not resp.ok:
				print(
					'Failed to get data from FI:\n'
					'%s\n'
					'-----------Response received------------\n'
					'%s\n'
					'------------End of response-------------', resp.url,
					resp.content.decode('utf-8', errors="ignore").strip())
				break
			return resp
		except requests.exceptions.Timeout as err:
			if attempt_num == MAX_RETRY:
				print(
					'Failed to get data from FI due to timeout, max retry exceeded:\n'
					'%s\n'
					'Error: %s', _construct_url(api, params), err)
				break
			delay = 5 * 2**attempt_num + random.randint(1, 10)
			logger.warning(
				'Failed to get data from FI due to timeout on attempt %d:\n'
				'%s\n'
				'retry in %ds...', attempt_num, _construct_url(api, params), delay)
			time.sleep(delay)
		except requests.exceptions.RequestException as err:
			print(
				'Failed to get data from FI due to unexpected error:\n'
				'%s\n'
				'Error: %s', _construct_url(api, params), err)
			break

	return None


def get_harness_pairs(project_name: str) -> dict[str, str]:
	INTROSPECTOR_FUNCTION_INFO = f'{INTROSPECTOR_ENDPOINT}/harness-source-and-executable'

	query_params: dict[str, Any] = {
			'project': project_name,
		}
	
	resp = query_introspector(INTROSPECTOR_FUNCTION_INFO, query_params)
	if resp is None:
		return {}
	resp_data = json.loads(resp.text)
	if "pairs" not in resp_data.keys():
		return {}

	harness_dict: dict[str, str] = {}
	for item in resp_data["pairs"]:
		if "executable" in item.keys() and "source" in item.keys():
			harness_dict[item["executable"]] = item["source"]

	return harness_dict

# res = get_harness_pairs("zydis")
# print(res)

# 	  "pairs": [
#     {
#       "executable": "ZydisFuzzReEncoding",
#       "source": "/src/zydis/tools/ZydisFuzzShared.c"
#     },
#     {
#       "executable": "ZydisFuzzEncoder",
#       "source": "/src/zydis/tools/ZydisFuzzShared.c"
#     },
#     {
#       "executable": "ZydisFuzzDecoder",
#       "source": "/src/zydis/tools/ZydisFuzzShared.c"
#     }
#   ],
import requests
import json
import os

SNYK_TOKEN=os.getenv("SNYK_TOKEN")
SNYK_ORG=os.getenv("SNYK_ORG")

url = f"https://snyk.io/api/v1/org/{SNYK_ORG}/projects"

payload={}
headers = {
  'Authorization': f'token {SNYK_TOKEN}',
}

url = f"https://api.snyk.io/v3/orgs/{SNYK_ORG}/projects?version=2021-06-04~beta"
def paginate_call(url):
    response_json = requests.request("GET", url, headers=headers, data=payload).json()
    data = response_json['data']
    while 'next' in response_json['links']:
        url = f"https://api.snyk.io/v3{response_json['links']['next']}"
        response_json = requests.request("GET", url, headers=headers, data=payload).json()
        data += response_json['data']
    return data

output = {}
for project in paginate_call(url):
    if project["attributes"]['name'].split(':')[0] not in output:
        output[project["attributes"]['name'].split(':')[0]] = []
    # Snyk Code
    if 'sast' in project['attributes']['type'].lower():
        url = f"https://api.snyk.io/v3/orgs/{SNYK_ORG}/issues?version=2021-08-20~experimental&project_id={project['id']}"
        for issue in paginate_call(url):
            url = f"https://api.snyk.io/v3/orgs/{SNYK_ORG}/issues/detail/code/{issue['id']}?version=2021-08-20~experimental&project_id={project['id']}"
            issue = requests.request("GET", url, headers=headers, data=payload).json()['data']
            ignore = {}
            if issue['attributes']['ignored']:
                url = f"https://snyk.io/api/v1/org/{SNYK_ORG}/project/{project['id']}/ignore/{issue['id']}"
                ignore = requests.request("GET", url, headers=headers, data=payload).json()[0]["*"]
            output[project["attributes"]['name'].split(':')[0]].append({
                "type": project['attributes']["type"],
                "project name": project["attributes"]["name"],
                "project origin": project["attributes"]["origin"],
                "project reference": project["attributes"]["targetReference"],
                "project id": project["id"],
                "project link": f"https://app.snyk.io/org/{SNYK_ORG}/project/{project['id']}",
                "ignored": issue["attributes"]["ignored"],
                "ignore reason": ignore["reason"] if issue["attributes"]["ignored"] else "",
                "file path": issue["attributes"]["primaryFilePath"],
                "title": issue["attributes"]["title"],
                "severity": issue["attributes"]["severity"],
                "remediation": "",
            })

    # OS, Container etc.
    else:
        url = f"https://snyk.io/api/v1/org/{SNYK_ORG}/project/{project['id']}/aggregated-issues"
        response = requests.request("POST", url, headers=headers, data=payload)
        for issue in response.json()['issues']:
            if issue['isIgnored']:
                url = f"https://snyk.io/api/v1/org/{SNYK_ORG}/project/{project['id']}/ignore/{issue['id']}"
                ignore = requests.request("GET", url, headers=headers, data=payload).json()[0]["*"]
            output[project["attributes"]['name'].split(':')[0]].append({
                "type": project['attributes']["type"],
                "project name": project["attributes"]["name"],
                "project origin": project["attributes"]["origin"],
                "project reference": project["attributes"]["targetReference"],
                "project id": project["id"],
                "project link": f"https://app.snyk.io/org/{SNYK_ORG}/project/{project['id']}",
                "ignored": issue["isIgnored"],
                "ignore reason": ignore["reason"] if issue["isIgnored"] else "",
                "file path": project["attributes"]["name"].split(":").pop(),
                "title": issue["issueData"]["title"],
                "severity": issue["issueData"]["severity"],
                "remediation": "",
            })

with open('output.json', 'w+') as f:
    output = json.dump(output, f)
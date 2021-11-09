import json

with open('output.json', 'r') as f:
    output = json.load(f)

for project in output:
    print(f"We found {len(output[project])} issues in the project: {project}")
    for issue in output[project]:
        print(f"\t {issue['severity']}    \t {issue['title']} ({issue['type']}): {issue['file path']}")
        if issue['ignored']:
           print(f"\t\tThis issue is ignored for the reason: {issue['ignore reason']}")
    print("\n")

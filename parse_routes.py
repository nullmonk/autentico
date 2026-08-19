import re

with open('pkg/cli/start.go', 'r') as f:
    content = f.read()

routes = []
for match in re.finditer(r'mux\.Handle\("([A-Z]+) (/admin/api/[^"]+)"', content):
    method, path = match.groups()
    # Normalize paths like /admin/api/users/{id} to /admin/api/users/* maybe?
    # No, the user wants EXACT methods based on what exists.
    # The requirement: "match ALL the API routes and methods, currently it cant do all of them"
    print(f'{{ value: "{path}:{method}", label: "{path} ({method})" }},')

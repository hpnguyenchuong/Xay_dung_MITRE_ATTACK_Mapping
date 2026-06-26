import sys

with open('drone.py', 'r', encoding='utf-8') as f:
    content = f.read()

import re

def replacer(match):
    query = match.group(0)
    if 'SELECT ' in query or 'execute("SELECT ' in query or 'execute(\'SELECT ' in query:
        return query.replace("WHERE drone_id != 'GLOBAL'", "WHERE 1=1").replace("AND drone_id != 'GLOBAL'", "")
    return query

new_content = []
for line in content.split('\n'):
    new_content.append(replacer(re.match(r'.*', line)))

with open('drone.py', 'w', encoding='utf-8') as f:
    f.write('\n'.join(new_content))
print('Replaced')

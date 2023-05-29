import os

for os_file in os.listdir(os.path.dirname(__file__)):
    if os_file.endswith(".py") and os_file not in ["__init__.py", "orc.py"]:
        try:
            exec(f"from tools import {os_file.split('.')[0]}")
        except Exception as e:
            print(f"Impossible to import {os_file}")
            print(e)
            continue

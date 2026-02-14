import os

development_folder = "D:/Training/Detection-Engg/Training/Python/detection-engineering1/development"

# Create folder if it doesn't exist
os.makedirs(development_folder, exist_ok=True)

# Sample TOML templates
sample_rules = [
    {
        "filename": "powershell_rule.toml",
        "name": "Suspicious PowerShell Execution",
        "author": ["Security Team"],
        "risk_score": 65,
        "severity": "high",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "sub_id": "T1059.001",
        "sub_name": "PowerShell"
    },
    {
        "filename": "ransomware_rule.toml",
        "name": "Ransomware File Extensions",
        "author": "Threat Intel",
        "risk_score": 85,
        "severity": "critical",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "sub_id": "none",
        "sub_name": "none"
    },
    {
        "filename": "lateral_movement.toml",
        "name": "SMB Lateral Movement",
        "author": ["Detection Team", "SOC"],
        "risk_score": 45,
        "severity": "medium",
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "sub_id": "T1021.002",
        "sub_name": "SMB/Windows Admin Shares"
    }
]

for rule in sample_rules:
    file_path = os.path.join(development_folder, rule["filename"])
    
    # Handle subtechnique section
    if rule["sub_id"] != "none":
        sub_section = f'''
[[rule.threat.technique.subtechnique]]
id = "{rule['sub_id']}"
name = "{rule['sub_name']}"'''
    else:
        sub_section = ""
    
    # Handle author as list or string
    if isinstance(rule["author"], list):
        author_str = str(rule["author"])
    else:
        author_str = f'"{rule["author"]}"'
    
    toml_content = f'''[metadata]
creation_date = "2024-02-14"

[rule]
name = "{rule['name']}"
author = {author_str}
risk_score = {rule['risk_score']}
severity = "{rule['severity']}"

[[rule.threat]]
framework = "MITRE ATT&CK"
tactic = {{ name = "{rule['tactic']}", id = "{rule['tactic_id']}" }}

[[rule.threat.technique]]
id = "{rule['technique_id']}"
name = "{rule['technique_name']}"{sub_section}
'''
    
    with open(file_path, 'w') as f:
        f.write(toml_content)
    
    print(f"Created: {rule['filename']}")

print(f"\n✅ Created {len(sample_rules)} test TOML files in: {development_folder}")
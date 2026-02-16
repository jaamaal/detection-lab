import tomllib
import os
import csv

# Author = Jamal Uddin Shaikh
# Configuration - CHANGE THIS TO YOUR DEVELOPMENT FOLDER PATH
INPUT_PATH = "detections/"  # Changed from 'metrics' to 'development'
#OUTPUT_PATH = os.path.join(INPUT_PATH, "All_Rules_Created.csv")  # CSV will be created in the same folder
OUTPUT_PATH = "metrics/All_Rules_Created.csv"

# Check if input path exists
if not os.path.exists(INPUT_PATH):
    print(f"ERROR: Path does not exist: {INPUT_PATH}")
    exit(1)

print(f"Scanning for TOML files in: {INPUT_PATH}")
rules_dict = {}
toml_count = 0

# Walk through directory (including subdirectories)
for root, dirs, files in os.walk(INPUT_PATH):
    for file in files:
        if file.endswith(".toml"):
            toml_count += 1
            full_path = os.path.join(root, file)
            print(f"Processing: {full_path}")
            
            try:
                with open(full_path, "rb") as toml:
                    alert = tomllib.load(toml)
                    
                    # Extract metadata with safe defaults
                    date = alert.get('metadata', {}).get('creation_date', 'unknown')
                    name = alert.get('rule', {}).get('name', 'unknown')
                    author = alert.get('rule', {}).get('author', 'unknown')
                    risk_score = alert.get('rule', {}).get('risk_score', '0')
                    severity = alert.get('rule', {}).get('severity', 'unknown')
                    
                    filtered_object_array = []
                    
                    # Process MITRE data
                    if 'rule' in alert and 'threat' in alert['rule']:
                        for threat in alert['rule']['threat']:
                            if threat.get('framework') == "MITRE ATT&CK":
                                technique = threat.get('technique', [{}])[0]
                                technique_id = technique.get('id', 'none')
                                technique_name = technique.get('name', 'none')
                                tactic = threat.get('tactic', {}).get('name', 'none')
                                
                                # Handle subtechnique
                                if 'subtechnique' in technique and technique['subtechnique']:
                                    sub = technique['subtechnique'][0]
                                    subtechnique_id = sub.get('id', 'none')
                                    subtechnique_name = sub.get('name', 'none')
                                else:
                                    subtechnique_id = 'none'
                                    subtechnique_name = 'none'
                                
                                technique_str = f"{technique_id} - {technique_name}"
                                subtech_str = f"{subtechnique_id} - {subtechnique_name}"
                                
                                obj = {
                                    'tactic': tactic, 
                                    'technique': technique_str, 
                                    'subtech': subtech_str
                                }
                                filtered_object_array.append(obj)
                    
                    # Store in dictionary
                    rules_dict[file] = {
                        'name': name, 
                        'date': date, 
                        'author': author, 
                        'risk_score': risk_score, 
                        'severity': severity, 
                        'mitre': filtered_object_array
                    }
                    
            except Exception as e:
                print(f"Error processing {file}: {e}")

print(f"\nFound {toml_count} TOML files")
print(f"Successfully processed {len(rules_dict)} files")

# Write to CSV
if rules_dict:
    with open(OUTPUT_PATH, "w", newline='', encoding='utf-8') as outF:
        writer = csv.writer(outF)
        writer.writerow(["name", "date", "author", "risk_score", "severity", "tactic", "technique", "subtechnique"])
        
        separator = "; "
        for filename, rule_data in rules_dict.items():
            date = rule_data['date']
            name = rule_data['name']
            
            # Handle author as string or list
            if isinstance(rule_data['author'], list):
                author = "; ".join(rule_data['author'])
            else:
                author = str(rule_data['author']).replace(",", ";")
            
            risk_score = str(rule_data['risk_score'])
            severity = rule_data['severity']
            
            tactic = []
            tech = []
            subtech = []
            
            for technique in rule_data['mitre']:
                tactic.append(technique['tactic'])
                tech.append(technique['technique'])
                subtech.append(technique['subtech'])
            
            writer.writerow([
                name, date, author, risk_score, severity,
                separator.join(tactic), separator.join(tech), separator.join(subtech)
            ])
    
    print(f"\n✅ CSV created successfully: {OUTPUT_PATH}")
    
    # Show summary
    print(f"\n📊 Summary:")
    print(f"  - Total TOML files found: {toml_count}")
    print(f"  - Successfully processed: {len(rules_dict)}")
    print(f"  - Output file: {OUTPUT_PATH}")
    
    # Show first few lines of CSV
    print("\n📄 First few lines of CSV:")
    with open(OUTPUT_PATH, 'r') as f:
        for i, line in enumerate(f):
            if i < 5:  # Show header + first 4 data rows
                print(line.strip())
            else:
                break
else:
    print("\n❌ No data to write to CSV. Check if TOML files exist and have correct format.")

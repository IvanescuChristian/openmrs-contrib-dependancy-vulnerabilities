import json
import requests
import time
import glob

def get_nvd_data(cve_id, retries=3):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if data.get('vulnerabilities'):
                    return data['vulnerabilities'][0]['cve']
                return None
            elif response.status_code in [403, 429]:
                print(f"Rate limit hit for {cve_id}. Maybe will add VeryFriendlyUser proxyapi if repeated issues are reported")
                time.sleep(10)
            else:
                print(f"Http error {response.status_code} for {cve_id}")
                return None
        except Exception as e:
            print(f"Conexion error for {cve_id}: {e}")
            time.sleep(5)
    return None

def extract_cwe(cve_data):
    cwes = []
    for w in cve_data.get('weaknesses', []):
        for desc in w.get('description', []):
            val = desc.get('value')
            if val and "NVD-CWE" not in val and val not in cwes:
                cwes.append(val)
    return cwes if cwes else None

def extract_score_and_severity(cve_data):
    metrics = cve_data.get('metrics', {})
    for cvss_ver in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
        if cvss_ver in metrics and len(metrics[cvss_ver]) > 0:
            metric_data = metrics[cvss_ver][0].get('cvssData', {})
            score = metric_data.get('baseScore')
            severity = metric_data.get('baseSeverity') or metrics[cvss_ver][0].get('baseSeverity')
            if score:
                return score, severity.capitalize() if severity else None
    return None, None

def extract_exploit(cve_data):
    if 'cisaExploitAdd' in cve_data or 'cisaVulnerabilityName' in cve_data:
        return "Yes"
        
    for ref in cve_data.get('references', []):
        tags = ref.get('tags', [])
        for tag in tags:
            if 'exploit' in tag.lower():
                return "Yes"
        if 'exploit' in ref.get('url', '').lower():
            return "Yes"
            
    return None

def extract_versions(cve_data):
    affected = []
    fixed_in = None
    
    for config in cve_data.get('configurations', []):
        for node in config.get('nodes', []):
            for match in node.get('cpeMatch', []):
                if match.get('vulnerable'):
                    v_start = match.get('versionStartIncluding')
                    v_end_exc = match.get('versionEndExcluding')
                    v_end_inc = match.get('versionEndIncluding')
                    
                    aff_str = ""
                    if v_start: 
                        aff_str += f">= {v_start}"
                        
                    if v_end_exc:
                        aff_str += f" and < {v_end_exc}" if aff_str else f"< {v_end_exc}"
                        if not fixed_in:
                            fixed_in = v_end_exc 
                    elif v_end_inc:
                        aff_str += f" and <= {v_end_inc}" if aff_str else f"<= {v_end_inc}"
                    
                    if not aff_str:
                        parts = match.get('criteria', '').split(':')
                        if len(parts) > 5 and parts[5] != '*':
                            aff_str = parts[5]
                            
                    if aff_str and aff_str not in affected:
                        affected.append(aff_str.strip(' and '))

    affected_str = ", ".join(affected) if affected else None
    return affected_str, fixed_in

def enrich_json_file(filepath):
    print(f"\nProcesez: {filepath}")
    with open(filepath, 'r', encoding='utf-8') as f:
        try:
            report = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error with Json parsing {filepath}: {e}")
            return

    if 'vulnerabilities' not in report:
        print("File does not contain 'vulnerabilities' section.")
        return

    modified = False
    vulnerabilities = report['vulnerabilities']
    
    for i in range(len(vulnerabilities)):
        vuln = vulnerabilities[i]
        
        raw_cve_id = vuln.get('name') or vuln.get('id')
        if not raw_cve_id:
            continue
            
        cve_id = str(raw_cve_id).strip()
        
        if vuln.get('name') and vuln['name'] != cve_id:
            report['vulnerabilities'][i]['name'] = cve_id
            modified = True
        if vuln.get('id') and vuln['id'] != cve_id:
            report['vulnerabilities'][i]['id'] = cve_id
            modified = True
            
        if not cve_id.startswith('CVE-'):
            continue

        if vuln.get('cwes') and vuln.get('cvssScore') and vuln.get('exploit') and vuln.get('vulnerableVersions') and vuln.get('fixedIn'):
            continue

        print(f"Aduc date pentru: {cve_id}")
        nvd_data = get_nvd_data(cve_id)
        
        if nvd_data:
            cwes = extract_cwe(nvd_data)
            score, severity = extract_score_and_severity(nvd_data)
            exploit = extract_exploit(nvd_data)
            affected, fixed = extract_versions(nvd_data)

            if cwes and not vuln.get('cwes'): 
                report['vulnerabilities'][i]['cwes'] = cwes
                print(f"   + CWE: {cwes}")
                modified = True
                
            if score and not vuln.get('cvssScore'): 
                report['vulnerabilities'][i]['cvssScore'] = score
                print(f"   + Score: {score}")
                modified = True
                
            if severity and (not vuln.get('severity') or vuln.get('severity') == 'Unknown'): 
                report['vulnerabilities'][i]['severity'] = severity
                modified = True
                
            if exploit and not vuln.get('exploit'): 
                report['vulnerabilities'][i]['exploit'] = exploit
                print(f"   + Exploit: Yes")
                modified = True
                
            if affected and not vuln.get('vulnerableVersions'): 
                report['vulnerabilities'][i]['vulnerableVersions'] = affected
                print(f"   + Affected: {affected}")
                modified = True
                
            if fixed and not vuln.get('fixedIn'): 
                report['vulnerabilities'][i]['fixedIn'] = fixed
                print(f"   + Fixed In: {fixed}")
                modified = True
                
        time.sleep(6) 

    if modified:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"File {filepath} succesfully revamped")
    else:
         print(f"{filepath} had no changes made")

if __name__ == "__main__":
    print("Drill time")
    target_files = [f for f in glob.glob('*.json') if "openmrs" in f or "billing" in f or "idgen" in f]
    
    if not target_files:
        print("Found no json files")
        
    for file in target_files:
        enrich_json_file(file)
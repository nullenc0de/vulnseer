import json
import re
import argparse
import subprocess
import tempfile
import os
import sys
from dataclasses import dataclass
from typing import List, Dict, Optional
from pathlib import Path

# Optional imports for AI providers
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

@dataclass
class ServiceInfo:
    host: str
    port: int
    service: str
    version: str
    banners: Dict[str, str]

class AIProvider:
    """Base class for AI providers"""
    
    def analyze_vulnerabilities(self, service: str, version: str, no_cves: bool = False) -> str:
        """Analyze vulnerabilities for a service version"""
        raise NotImplementedError
    
    def parse_ai_analysis(self, analysis: str, no_cves: bool = False) -> Dict:
        """Parse AI analysis into structured data"""
        raise NotImplementedError

class AnthropicProvider(AIProvider):
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        if not ANTHROPIC_AVAILABLE:
            raise ImportError("Anthropic library not installed. Run: pip install anthropic")
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def analyze_vulnerabilities(self, service: str, version: str, no_cves: bool = False) -> str:
        """Analyze vulnerabilities for a service version"""
        
        if no_cves:
            prompt = f"""You are a cybersecurity expert analyzing software security posture.

SERVICE: {service}
VERSION: {version}

INSTRUCTIONS - RISK ASSESSMENT ONLY (NO CVE REPORTING):
- Do NOT mention any specific CVEs
- Focus on general risk assessment based on software age and support status
- Provide actionable security recommendations

Please assess:
1. Overall risk level based on software age and maintenance status
2. General security concerns for software of this vintage
3. Vendor support and maintenance status
4. Upgrade recommendations
5. Deployment security considerations

Provide a clear risk assessment without specific vulnerability references."""
        else:
            prompt = f"""You are a cybersecurity expert analyzing software vulnerabilities. 

SERVICE: {service}
VERSION: {version}

CRITICAL INSTRUCTION - DO NOT GUESS CVES:
- ONLY mention a CVE if you are 100% certain it affects this EXACT service name and version
- DO NOT extrapolate CVEs from similar products or timeframes
- DO NOT guess CVEs based on software age
- If you're unsure about ANY CVE, do not mention it
- It's better to report "No specific CVEs verified" than to list wrong ones

FOCUS ON:
1. Overall risk assessment based on software age and support status
2. General security posture for software of this era
3. Vendor support and patch availability
4. Upgrade recommendations

Please provide:
1. Overall risk level (Critical/High/Medium/Low/Unknown) - base this on software age and maintenance status
2. CVE Status: "No verified CVEs for this exact service/version" (unless you're 100% certain)
3. Age-based risk assessment
4. Vendor support status
5. Specific upgrade recommendations

Example response format:
- Risk Level: [Critical/High/etc] based on age and support status
- CVE Status: No verified CVEs for this exact service/version combination
- Age Assessment: This appears to be very old software from ~[year]
- Support Status: Likely end-of-life
- Recommendation: Immediate replacement recommended

Be honest about limitations in CVE verification rather than guessing."""

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        except Exception as e:
            # Try fallback models if primary fails
            fallback_models = [
                "claude-3-5-sonnet-20241022",
                "claude-3-sonnet-20240229", 
                "claude-3-haiku-20240307"
            ]
            
            for fallback in fallback_models:
                try:
                    response = self.client.messages.create(
                        model=fallback,
                        max_tokens=1000,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    return response.content[0].text
                except:
                    continue
            
            return f"Error: {str(e)}"

    def parse_ai_analysis(self, analysis: str, no_cves: bool = False) -> Dict:
        """Parse AI analysis into structured data with validation"""
        # Default values
        result = {
            'risk': 'Unknown',
            'cves': [],
            'exploitable': False,
            'exploits_available': False,
            'patch_status': 'Unknown',
            'raw_analysis': analysis
        }
        
        try:
            # Extract risk level
            risk_patterns = [
                r'(?:risk|severity).*?(Critical|High|Medium|Low)',
                r'(Critical|High|Medium|Low).*?risk',
                r'Overall.*?(Critical|High|Medium|Low)'
            ]
            
            for pattern in risk_patterns:
                match = re.search(pattern, analysis, re.IGNORECASE)
                if match:
                    result['risk'] = match.group(1).title()
                    break
            
            # Only extract CVEs if not disabled
            if not no_cves:
                # Extract CVEs with basic validation and warnings
                cve_pattern = r'CVE-\d{4}-\d{4,7}'
                cves = re.findall(cve_pattern, analysis)
                
                # Validate CVEs (basic check for reasonable year range)
                valid_cves = []
                current_year = 2025
                for cve in cves:
                    year = int(cve.split('-')[1])
                    if 1999 <= year <= current_year:  # Reasonable CVE year range
                        valid_cves.append(cve)
                
                # Add warning if CVEs found (since AI tends to hallucinate them)
                if valid_cves:
                    print(f"  ⚠️  Warning: {len(valid_cves)} CVEs mentioned - VERIFY INDEPENDENTLY")
                    print(f"  CVEs to verify: {', '.join(valid_cves)}")
                
                result['cves'] = list(set(valid_cves))  # Remove duplicates
            
            # Extract boolean indicators
            exploitable_indicators = [
                r'exploitable.*?(?:yes|true)',
                r'(?:yes|true).*?exploitable',
                r'can be exploited',
                r'is exploitable'
            ]
            
            for pattern in exploitable_indicators:
                if re.search(pattern, analysis, re.IGNORECASE):
                    result['exploitable'] = True
                    break
            
            exploit_indicators = [
                r'exploits?.*?(?:available|exist|public)',
                r'(?:available|exist|public).*?exploits?',
                r'metasploit',
                r'exploit.*?code'
            ]
            
            for pattern in exploit_indicators:
                if re.search(pattern, analysis, re.IGNORECASE):
                    result['exploits_available'] = True
                    break
            
            # Extract patch status
            patch_indicators = [
                (r'patch.*?(?:available|exists)', 'Available'),
                (r'(?:available|exists).*?patch', 'Available'),
                (r'upgrade.*?(?:available|recommended)', 'Available'),
                (r'no.*?patch', 'Unavailable'),
                (r'patch.*?(?:unavailable|none)', 'Unavailable')
            ]
            
            for pattern, status in patch_indicators:
                if re.search(pattern, analysis, re.IGNORECASE):
                    result['patch_status'] = status
                    break
                    
        except Exception as e:
            print(f"  Warning: Error parsing AI analysis: {e}")
            
        return result

class OpenAIProvider(AIProvider):
    def __init__(self, api_key: str, model: str = "gpt-4"):
        if not OPENAI_AVAILABLE:
            raise ImportError("OpenAI library not installed. Run: pip install openai")
        self.client = openai.OpenAI(api_key=api_key)
        self.model = model

    def analyze_vulnerabilities(self, service: str, version: str, no_cves: bool = False) -> str:
        """Analyze vulnerabilities for a service version"""
        
        if no_cves:
            prompt = f"""You are a cybersecurity expert analyzing software security posture.

SERVICE: {service}
VERSION: {version}

INSTRUCTIONS - RISK ASSESSMENT ONLY (NO CVE REPORTING):
- Do NOT mention any specific CVEs
- Focus on general risk assessment based on software age and support status
- Provide actionable security recommendations

Please assess:
1. Overall risk level based on software age and maintenance status
2. General security concerns for software of this vintage
3. Vendor support and maintenance status
4. Upgrade recommendations
5. Deployment security considerations

Provide a clear risk assessment without specific vulnerability references."""
        else:
            prompt = f"""You are a cybersecurity expert analyzing software vulnerabilities. 

SERVICE: {service}
VERSION: {version}

CRITICAL INSTRUCTION - DO NOT GUESS CVES:
- ONLY mention a CVE if you are 100% certain it affects this EXACT service name and version
- DO NOT extrapolate CVEs from similar products or timeframes
- DO NOT guess CVEs based on software age
- If you're unsure about ANY CVE, do not mention it
- It's better to report "No specific CVEs verified" than to list wrong ones

Be honest about limitations in CVE verification rather than guessing."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error: {str(e)}"
    
    def parse_ai_analysis(self, analysis: str, no_cves: bool = False) -> Dict:
        """Parse AI analysis into structured data with validation"""
        # Default values
        result = {
            'risk': 'Unknown',
            'cves': [],
            'exploitable': False,
            'exploits_available': False,
            'patch_status': 'Unknown',
            'raw_analysis': analysis
        }
        
        try:
            # Extract risk level
            risk_patterns = [
                r'(?:risk|severity).*?(Critical|High|Medium|Low)',
                r'(Critical|High|Medium|Low).*?risk',
                r'Overall.*?(Critical|High|Medium|Low)'
            ]
            
            for pattern in risk_patterns:
                match = re.search(pattern, analysis, re.IGNORECASE)
                if match:
                    result['risk'] = match.group(1).title()
                    break
            
            # Only extract CVEs if not disabled
            if not no_cves:
                # Extract CVEs with basic validation and warnings
                cve_pattern = r'CVE-\d{4}-\d{4,7}'
                cves = re.findall(cve_pattern, analysis)
                
                # Validate CVEs (basic check for reasonable year range)
                valid_cves = []
                current_year = 2025
                for cve in cves:
                    year = int(cve.split('-')[1])
                    if 1999 <= year <= current_year:  # Reasonable CVE year range
                        valid_cves.append(cve)
                
                # Add warning if CVEs found (since AI tends to hallucinate them)
                if valid_cves:
                    print(f"  ⚠️  Warning: {len(valid_cves)} CVEs mentioned - VERIFY INDEPENDENTLY")
                    print(f"  CVEs to verify: {', '.join(valid_cves)}")
                
                result['cves'] = list(set(valid_cves))  # Remove duplicates
            
            # Extract boolean indicators
            exploitable_indicators = [
                r'exploitable.*?(?:yes|true)',
                r'(?:yes|true).*?exploitable',
                r'can be exploited',
                r'is exploitable'
            ]
            
            for pattern in exploitable_indicators:
                if re.search(pattern, analysis, re.IGNORECASE):
                    result['exploitable'] = True
                    break
            
            exploit_indicators = [
                r'exploits?.*?(?:available|exist|public)',
                r'(?:available|exist|public).*?exploits?',
                r'metasploit',
                r'exploit.*?code'
            ]
            
            for pattern in exploit_indicators:
                if re.search(pattern, analysis, re.IGNORECASE):
                    result['exploits_available'] = True
                    break
            
            # Extract patch status
            patch_indicators = [
                (r'patch.*?(?:available|exists)', 'Available'),
                (r'(?:available|exists).*?patch', 'Available'),
                (r'upgrade.*?(?:available|recommended)', 'Available'),
                (r'no.*?patch', 'Unavailable'),
                (r'patch.*?(?:unavailable|none)', 'Unavailable')
            ]
            
            for pattern, status in patch_indicators:
                if re.search(pattern, analysis, re.IGNORECASE):
                    result['patch_status'] = status
                    break
                    
        except Exception as e:
            print(f"  Warning: Error parsing AI analysis: {e}")
            
        return result

class GroqProvider(AIProvider):
    def __init__(self, api_key: str, model: str = "mixtral-8x7b-32768"):
        if not REQUESTS_AVAILABLE:
            raise ImportError("Requests library not installed. Run: pip install requests")
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.groq.com/openai/v1"

    def analyze_vulnerabilities(self, service: str, version: str, no_cves: bool = False) -> str:
        """Analyze vulnerabilities for a service version"""
        
        if no_cves:
            prompt = f"""You are a cybersecurity expert analyzing software security posture.

SERVICE: {service}
VERSION: {version}

INSTRUCTIONS - RISK ASSESSMENT ONLY (NO CVE REPORTING):
- Do NOT mention any specific CVEs
- Focus on general risk assessment based on software age and support status
- Provide actionable security recommendations

Please assess:
1. Overall risk level based on software age and maintenance status
2. General security concerns for software of this vintage
3. Vendor support and maintenance status
4. Upgrade recommendations
5. Deployment security considerations

Provide a clear risk assessment without specific vulnerability references."""
        else:
            prompt = f"""You are a cybersecurity expert analyzing software vulnerabilities. 

SERVICE: {service}
VERSION: {version}

CRITICAL INSTRUCTION - DO NOT GUESS CVES:
- ONLY mention a CVE if you are 100% certain it affects this EXACT service name and version
- DO NOT extrapolate CVEs from similar products or timeframes
- DO NOT guess CVEs based on software age
- If you're unsure about ANY CVE, do not mention it
- It's better to report "No specific CVEs verified" than to list wrong ones

Be honest about limitations in CVE verification rather than guessing."""

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1000
        }
        
        response = requests.post(f"{self.base_url}/chat/completions", 
                               headers=headers, json=data)
        return response.json()["choices"][0]["message"]["content"]
    
    def parse_ai_analysis(self, analysis: str, no_cves: bool = False) -> Dict:
        """Parse AI analysis into structured data with validation"""
        # Default values
        result = {
            'risk': 'Unknown',
            'cves': [],
            'exploitable': False,
            'exploits_available': False,
            'patch_status': 'Unknown',
            'raw_analysis': analysis
        }
        
        try:
            # Extract risk level
            risk_patterns = [
                r'(?:risk|severity).*?(Critical|High|Medium|Low)',
                r'(Critical|High|Medium|Low).*?risk',
                r'Overall.*?(Critical|High|Medium|Low)'
            ]
            
            for pattern in risk_patterns:
                match = re.search(pattern, analysis, re.IGNORECASE)
                if match:
                    result['risk'] = match.group(1).title()
                    break
            
            # Only extract CVEs if not disabled
            if not no_cves:
                # Extract CVEs with basic validation and warnings
                cve_pattern = r'CVE-\d{4}-\d{4,7}'
                cves = re.findall(cve_pattern, analysis)
                
                # Validate CVEs (basic check for reasonable year range)
                valid_cves = []
                current_year = 2025
                for cve in cves:
                    year = int(cve.split('-')[1])
                    if 1999 <= year <= current_year:  # Reasonable CVE year range
                        valid_cves.append(cve)
                
                # Add warning if CVEs found (since AI tends to hallucinate them)
                if valid_cves:
                    print(f"  ⚠️  Warning: {len(valid_cves)} CVEs mentioned - VERIFY INDEPENDENTLY")
                    print(f"  CVEs to verify: {', '.join(valid_cves)}")
                
                result['cves'] = list(set(valid_cves))  # Remove duplicates
            
            # Extract boolean indicators
            exploitable_indicators = [
                r'exploitable.*?(?:yes|true)',
                r'(?:yes|true).*?exploitable',
                r'can be exploited',
                r'is exploitable'
            ]
            
            for pattern in exploitable_indicators:
                if re.search(pattern, analysis, re.IGNORECASE):
                    result['exploitable'] = True
                    break
            
            exploit_indicators = [
                r'exploits?.*?(?:available|exist|public)',
                r'(?:available|exist|public).*?exploits?',
                r'metasploit',
                r'exploit.*?code'
            ]
            
            for pattern in exploit_indicators:
                if re.search(pattern, analysis, re.IGNORECASE):
                    result['exploits_available'] = True
                    break
            
            # Extract patch status
            patch_indicators = [
                (r'patch.*?(?:available|exists)', 'Available'),
                (r'(?:available|exists).*?patch', 'Available'),
                (r'upgrade.*?(?:available|recommended)', 'Available'),
                (r'no.*?patch', 'Unavailable'),
                (r'patch.*?(?:unavailable|none)', 'Unavailable')
            ]
            
            for pattern, status in patch_indicators:
                if re.search(pattern, analysis, re.IGNORECASE):
                    result['patch_status'] = status
                    break
                    
        except Exception as e:
            print(f"  Warning: Error parsing AI analysis: {e}")
            
        return result

class VulnerabilityScanner:
    def __init__(self, providers: List[AIProvider]):
        self.providers = providers

    def parse_targets(self, target_input: str) -> List[str]:
        """Parse target input (file, CIDR, single host)"""
        targets = []
        
        # Check if it's a file
        if os.path.isfile(target_input):
            with open(target_input, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        else:
            # Single target or CIDR
            targets = [target_input.strip()]
        
        return targets

    def run_nmap_scan(self, targets: List[str], ports: str = None) -> str:
        """Run nmap scan with version detection"""
        print(f"Scanning {len(targets)} target(s)...")
        
        # Create temporary target file
        temp_targets = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        for target in targets:
            temp_targets.write(f"{target}\n")
        temp_targets.close()
        
        # Create temporary output file
        temp_output = tempfile.NamedTemporaryFile(delete=False, suffix='.nmap')
        temp_output.close()
        
        try:
            # Build nmap command - use built-in version detection instead of NSE script
            cmd = [
                'nmap',
                '-sV',  # Version detection
                '-sC',  # Default scripts for additional info
                '-iL', temp_targets.name,  # Input from file
                '-oA', temp_output.name[:-5],  # Output all formats
            ]
            
            # Add port specification
            if ports:
                cmd.extend(['-p', ports])
            else:
                cmd.extend(['-p-'])  # Scan all ports
            
            print(f"Running: {' '.join(cmd)}")
            
            # Run nmap
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            if result.returncode != 0:
                print(f"Nmap error: {result.stderr}")
                return None
            
            # Read the .nmap output file
            nmap_file = temp_output.name[:-5] + '.nmap'
            if os.path.exists(nmap_file):
                with open(nmap_file, 'r') as f:
                    return f.read()
            else:
                return result.stdout
                
        except subprocess.TimeoutExpired:
            print("Nmap scan timed out after 1 hour")
            return None
        except FileNotFoundError:
            print("Error: nmap not found. Please install nmap.")
            sys.exit(1)
        finally:
            # Cleanup temp files
            try:
                os.unlink(temp_targets.name)
                for ext in ['.nmap', '.xml', '.gnmap']:
                    f = temp_output.name[:-5] + ext
                    if os.path.exists(f):
                        os.unlink(f)
            except:
                pass

    def parse_nmap_output(self, nmap_output: str) -> List[Dict]:
        """Extract version data from standard nmap output"""
        if not nmap_output:
            return []
        
        services = []
        current_host = None
        
        # Parse standard nmap output line by line
        for line in nmap_output.split('\n'):
            line = line.strip()
            
            # Extract host IP from "Nmap scan report for" line
            host_match = re.search(r'Nmap scan report for (.+)', line)
            if host_match:
                host_info = host_match.group(1)
                # Extract IP if format is "domain (IP)" or just use the string
                ip_match = re.search(r'\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)', host_info)
                current_host = ip_match.group(1) if ip_match else host_info.split()[0]
                continue
            
            # Parse service lines like "22/tcp open ssh OpenSSH 7.4 (protocol 2.0)"
            service_match = re.search(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(.+)', line)
            if service_match and current_host:
                port = int(service_match.group(1))
                protocol = service_match.group(2)
                service_name = service_match.group(3)
                version_info = service_match.group(4)
                
                # Extract product and version from version_info
                # Examples:
                # "OpenSSH 7.4 (protocol 2.0)" 
                # "GlobalScape CuteFTP sshd (sshlib 1.82; protocol 2.0)"
                # "Apache httpd 2.4.41 ((Ubuntu))"
                
                product = None
                version = None
                
                # Handle complex cases like "GlobalScape CuteFTP sshd (sshlib 1.82; protocol 2.0)"
                if '(' in version_info:
                    # Split on first parenthesis
                    parts = version_info.split('(', 1)
                    product_part = parts[0].strip()
                    version_part = parts[1].rstrip(')')
                    
                    # Try to extract version from the parenthetical part first
                    version_match = re.search(r'([0-9]+\.[0-9]+(?:\.[0-9]+)*)', version_part)
                    if version_match:
                        version = version_match.group(1)
                        product = product_part
                    else:
                        # Try to extract version from product part
                        version_match = re.search(r'([0-9]+\.[0-9]+(?:\.[0-9]+)*)', product_part)
                        if version_match:
                            version = version_match.group(1)
                            product = re.sub(r'\s*[0-9]+\.[0-9]+(?:\.[0-9]+)*\s*', '', product_part).strip()
                        else:
                            product = product_part
                            version = "unknown"
                else:
                    # No parentheses - try simple pattern like "OpenSSH 7.4"
                    version_match = re.search(r'(.+?)\s+([0-9]+\.[0-9]+(?:\.[0-9]+)*)', version_info)
                    if version_match:
                        product = version_match.group(1).strip()
                        version = version_match.group(2).strip()
                    else:
                        product = version_info
                        version = "unknown"
                
                # If no version extracted, use the whole string as product
                if not product:
                    product = version_info
                    version = "unknown"
                
                # Debug output
                print(f"  Parsed: {product} -> {version}")
                
                services.append({
                    'service': product.lower().replace(' ', '_'),
                    'version': version,
                    'port': port,
                    'host': current_host,
                    'raw_version': version_info  # Keep original for reference
                })
        
        return services

    def scan_and_analyze(self, target_input: str, ports: str = None, no_cves: bool = False) -> List[Dict]:
        """Complete scanning and analysis workflow"""
        targets = self.parse_targets(target_input)
        nmap_output = self.run_nmap_scan(targets, ports)
        
        if not nmap_output:
            print("No scan results to analyze")
            return []
        
        services = self.parse_nmap_output(nmap_output)
        
        if not services:
            print("No services with version info found")
            return []
        
        print(f"Found {len(services)} services to analyze...")
        
        results = []
        for i, service in enumerate(services, 1):
            print(f"[Provider {i}] Analyzing {service['service']} {service['version']}...")
            
            # Get analysis from first available provider
            provider = self.providers[0]  # Use first provider for now
            analysis_text = provider.analyze_vulnerabilities(
                service['service'], 
                service['version'],
                no_cves
            )
            analysis = provider.parse_ai_analysis(analysis_text, no_cves)
            
            results.append({
                'host': service['host'],
                'port': service['port'],
                'service': service['service'],
                'version': service['version'],
                'analysis': analysis
            })
        
        return results

    def generate_report(self, results: List[Dict], output_file: str = None, no_cves: bool = False):
        """Generate final vulnerability report"""
        report = "VULNERABILITY SCAN REPORT\n"
        report += "=" * 50 + "\n"
        report += f"Total Services Analyzed: {len(results)}\n"
        
        if not no_cves:
            report += "\n⚠️  IMPORTANT DISCLAIMER:\n"
            report += "- CVE information should be independently verified\n"
            report += "- Risk assessments are based on software age and general security posture\n"
            report += "- Always consult vendor security advisories for authoritative information\n"
        else:
            report += "\n📊 RISK ASSESSMENT MODE:\n"
            report += "- CVE reporting disabled for conservative analysis\n"
            report += "- Risk assessments based on software age and maintenance status\n"
            report += "- Verify specific vulnerabilities independently if needed\n"
        
        report += "=" * 50 + "\n"
        
        for result in results:
            report += f"\nHost: {result['host']}:{result['port']}\n"
            report += f"Service: {result['service']} {result['version']}\n"
            
            # Add version age indicator
            version_age = self.estimate_version_age(result['service'], result['version'])
            if version_age:
                report += f"Estimated Age: {version_age}\n"
            
            report += f"Risk: {result['analysis']['risk']}\n"
            
            if not no_cves:
                if result['analysis']['cves']:
                    report += f"CVEs: {', '.join(result['analysis']['cves'])} ⚠️ VERIFY INDEPENDENTLY\n"
                else:
                    report += f"CVEs: None verified for this exact service/version\n"
            else:
                report += f"CVEs: Disabled (risk assessment mode)\n"
                
            report += f"Exploitable: {result['analysis']['exploitable']}\n"
            report += f"Exploits Available: {result['analysis']['exploits_available']}\n"
            report += f"Patch Status: {result['analysis']['patch_status']}\n"
            
            # Add raw analysis for detailed info
            if 'raw_analysis' in result['analysis']:
                report += f"\nDetailed Analysis:\n{result['analysis']['raw_analysis']}\n"
            
            report += "-" * 50 + "\n"
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"\nReport saved to: {output_file}")
        else:
            print(report)
    
    def estimate_version_age(self, service: str, version: str) -> str:
        """Estimate software age based on version patterns"""
        try:
            # Extract year from version if present
            year_match = re.search(r'20(\d{2})', version)
            if year_match:
                year = 2000 + int(year_match.group(1))
                age = 2025 - year
                if age > 5:
                    return f"~{age} years (Very Old)"
                elif age > 2:
                    return f"~{age} years (Outdated)"
                else:
                    return f"~{age} years (Recent)"
            
            # Special patterns for known old software
            if 'globalscape' in service.lower() and '1.82' in version:
                return "~19 years (Very Old - circa 2006)"
            
            # Version patterns that suggest age
            if re.match(r'^[01]\.\d+', version):  # 0.x or 1.x versions
                return "Potentially Old (low version number)"
                
        except Exception:
            pass
        
        return None

    parser = argparse.ArgumentParser(description="AI-Powered Vulnerability Scanner")
    parser.add_argument("targets", help="Target IP/CIDR/hostname or file containing targets")
    parser.add_argument("--ports", "-p", help="Port specification (e.g., '22,80,443' or '1-1000')")
    parser.add_argument("--openai-key", help="OpenAI API key")
    parser.add_argument("--anthropic-key", help="Anthropic API key") 
    parser.add_argument("--groq-key", help="Groq API key")
    parser.add_argument("--output", "-o", help="Output report file")
    parser.add_argument("--providers", nargs="+", choices=["openai", "anthropic", "groq"], 
                       default=["openai"], help="AI providers to use")
    parser.add_argument("--no-cves", action="store_true", 
                       help="Disable CVE reporting (more conservative, risk assessment only)")
    
    args = parser.parse_args()
    
    # Initialize providers based on arguments
    providers = []
    
    if "openai" in args.providers and args.openai_key:
        try:
            providers.append(OpenAIProvider(args.openai_key))
        except ImportError as e:
            print(f"OpenAI Error: {e}")
    
    if "anthropic" in args.providers and args.anthropic_key:
        try:
            providers.append(AnthropicProvider(args.anthropic_key))
        except ImportError as e:
            print(f"Anthropic Error: {e}")
    
    if "groq" in args.providers and args.groq_key:
        try:
            providers.append(GroqProvider(args.groq_key))
        except ImportError as e:
            print(f"Groq Error: {e}")
    
    if not providers:
        print("Error: No valid AI providers configured")
        print("\nTo install dependencies:")
        print("  pip install openai anthropic requests")
        print("\nExample usage:")
        print("  python3 vuln-scanner.py 192.168.1.0/24 --openai-key YOUR_KEY")
        #return
    
    print(f"Using {len(providers)} AI provider(s)")
    
    # Run complete workflow
    scanner = VulnerabilityScanner(providers)
    results = scanner.scan_and_analyze(args.targets, args.ports, args.no_cves)
    scanner.generate_report(results, args.output, args.no_cves)

if __name__ == "__main__":
    main()

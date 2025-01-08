from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import subprocess
import os
import re
import logging
from pathlib import Path
from datetime import timedelta

# Configure logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Configure app and CSRF protection
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Basic config only
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

TOPOLOGY_DIR = Path('/root/nokia-basic-dci-lab/').resolve()

def validate_topology_file(filename):
    """Validate topology file path"""
    if not filename or '..' in filename:
        return False
    file_path = TOPOLOGY_DIR / filename
    return file_path.is_file() and file_path.suffix in ('.yml', '.yaml')

@app.route('/')
def index():
    try:
        topology_files = [f for f in os.listdir(TOPOLOGY_DIR) if f.endswith(('.yml', '.yaml'))]
        return render_template('index.html', 
                             topology_files=topology_files, 
                             topo_selected='topo_file' in session)
    except Exception as e:
        logging.error(f"Error in index route: {e}")
        flash('Error loading topology files', 'error')
        return redirect(url_for('index'))

# Error handlers
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    logging.error(f"CSRF error: {e}")
    return render_template('error.html', message="CSRF token missing or invalid"), 400

@app.route('/set-topology', methods=['POST'])
def set_topology():
    try:
        topo_file = request.form.get('topo_file')
        if not topo_file:
            flash('No topology file selected', 'error')
            return redirect(url_for('index'))

        if validate_topology_file(topo_file):
            topo_path = str(TOPOLOGY_DIR / topo_file)
            session['topo_file'] = topo_path
            flash('Topology file selected successfully', 'success')
        else:
            flash('Invalid topology file selected', 'error')
    except Exception as e:
        logging.error(f"Error setting topology: {e}")
        flash('Error setting topology file', 'error')
    
    return redirect(url_for('index'))

def run_fcli_command(command):
    """Run command with error handling"""
    try:
        logging.info(f"Executing command: {' '.join(command)}")
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=30
        )
        output = result.stdout.strip()
        if output.endswith("\x1b[0m"):
            output = output[:-4]
        return output
    except subprocess.TimeoutExpired:
        logging.error("Command execution timed out")
        return "Error: Command execution timed out"
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {e.stderr}")
        return f"Error executing command: {e.stderr}"
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return f"Unexpected error occurred: {str(e)}"

def process_filter_option(filter_value):
    """Process filter value keeping commas intact"""
    if not filter_value:
        return []
    
    # Split by comma and clean
    filters = [f.strip() for f in filter_value.split(',')]
    
    # Build command array
    result = []
    for f in filters:
        if f:
            result.extend(['-f', f])
    return result

def format_command_output(output):
    """Format command output as string"""
    return output

@app.route('/command/<cmd>', methods=['GET', 'POST'])
def command(cmd):
    if not session.get('topo_file'):
        flash('Please select a topology file first', 'error')
        return redirect(url_for('index'))
    
    topo_file = session.get('topo_file')
    if not topo_file:
        flash('Please select a topology file first.')
        return redirect(url_for('index'))
    
    help_command = ['fcli', '-t', topo_file, cmd, '--help']
    help_output = run_fcli_command(help_command)
    options = parse_help_output(help_output)
    
    if request.method == 'POST':
        data = request.get_json()
        options_input = data.get('options', {})
        command = ['fcli', '-t', topo_file, cmd]
        
        # Build command with options
        for option, value in options_input.items():
            if value:
                command.extend([option, value])
                    
        output = run_fcli_command(command)
        return jsonify({'output': output})
    
    return render_template('command.html', command=cmd, options=options)

def parse_help_output(help_output):
    options = []
    # Updated pattern to split on comma and take first option
    option_pattern = re.compile(r'  (-[\w-]+)(?:,\s+--[\w-]+)?\s+(.+)$', re.MULTILINE)
    for match in option_pattern.finditer(help_output):
        options.append({
            'option': match.group(1).strip(),  # Take only first option without comma
            'description': match.group(2).strip()
        })
    return options

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
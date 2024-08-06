from flask import render_template, url_for, flash, redirect, request, jsonify
from app import app, db, bcrypt, socketio
from app.forms import RegistrationForm, LoginForm, AddRouterForm, AddServerForm, AddWGConnectionForm
from app.models import User, Router, Server, WireGuardConnection
from flask_login import login_user, current_user, logout_user, login_required
import subprocess
import platform
import paramiko
import logging
import ipaddress
import requests
from flask_socketio import SocketIO, emit

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Initialize Flask-SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# Function to execute SSH commands
def run_remote_command(client, command):
    stdin, stdout, stderr = client.exec_command(command)
    stdout.channel.recv_exit_status()  # Wait for command to complete
    error = stderr.read().decode().strip()
    if error:
        logging.error(f"Error: {error}")
        raise Exception(f"Error executing command: {command}, Error: {error}")
    return stdout.read().decode().strip()

def execute_ssh_commands(ip, username, password, commands):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password)
        for command in commands:
            logging.info(f"Executing command: {command}")
            run_remote_command(client, command)
        client.close()
        return "Success"
    except Exception as e:
        logging.error(f"SSH command execution failed: {e}")
        return "Failed"

def get_network_interface(ip, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password)
        interface = run_remote_command(client, "ip -o -4 route show to default | awk '{print $5}'")
        client.close()
        if interface:
            logging.info(f"Network interface found: {interface}")
        else:
            logging.warning(f"No network interface found for server at {ip}")
        return interface
    except Exception as e:
        logging.error(f"SSH command execution failed: {e}")
        return None

def check_ssh_connection(ip, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=10)
        client.close()
        return "Connected"
    except Exception as e:
        logging.error(f"SSH connection failed: {e}")
        return "Disconnected"

def find_next_available_ip(server):
    connections = WireGuardConnection.query.filter_by(server_id=server.id).all()
    used_ips = {conn.client_ip for conn in connections}
    subnet = ipaddress.ip_network(server.wireguard_address, strict=False)
    for ip in subnet.hosts():
        if str(ip).endswith(".1"):  # Skip the .1 IP
            continue
        if str(ip) not in used_ips:
            return str(ip)
    return None

def fetch_wg_connections(ip, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password)
        output = run_remote_command(client, "sudo wg show")
        client.close()
        return output
    except Exception as e:
        logging.error(f"Fetching WireGuard connections failed: {e}")
        return None

def parse_wg_show_output(output):
    connections = []
    current_peer = None
    for line in output.splitlines():
        if line.startswith("peer:"):
            if current_peer:
                connections.append(current_peer)
            current_peer = {"peer": line.split()[1]}
        elif line.startswith("endpoint:") and current_peer:
            current_peer["endpoint"] = line.split()[1]
        elif line.startswith("allowed ips:") and current_peer:
            current_peer["allowed_ips"] = line.split()[2]
    if current_peer:
        connections.append(current_peer)
    return connections

def fetch_server_public_key(ip, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password)
        private_key = run_remote_command(client, "sudo cat /etc/wireguard/wg0.conf | grep 'PrivateKey' | awk '{print $3}'")
        public_key = run_remote_command(client, f"echo {private_key} | wg pubkey")
        client.close()
        return public_key.strip()
    except Exception as e:
        logging.error(f"Fetching server public key failed: {e}")
        return None

@app.route('/')
def index():
    form = LoginForm()
    return render_template('index.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if not current_user.is_admin:
        flash('Only administrators can access this page.', 'danger')
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    routers = Router.query.all()
    servers = Server.query.all()
    connections = WireGuardConnection.query.all()
    return render_template('dashboard.html', routers=routers, servers=servers, connections=connections)

@app.route('/add_router', methods=['GET', 'POST'])
@login_required
def add_router():
    form = AddRouterForm()
    if form.validate_on_submit():
        router = Router(name=form.name.data, ip_address=form.ip_address.data, username=form.username.data, password=form.password.data)
        db.session.add(router)
        db.session.commit()
        flash('Router has been added!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_router.html', title='Add Router', form=form)

@app.route('/add_server', methods=['GET', 'POST'])
@login_required
def add_server():
    form = AddServerForm()
    if form.validate_on_submit():
        server = Server(name=form.name.data, ip_address=form.ip_address.data, username=form.username.data, password=form.password.data, wireguard_address=form.wireguard_address.data)
        db.session.add(server)
        db.session.commit()
        flash('Server has been added!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_server.html', title='Add Server', form=form)

@app.route('/edit_server/<int:server_id>', methods=['GET', 'POST'])
@login_required
def edit_server(server_id):
    server = Server.query.get_or_404(server_id)
    form = AddServerForm()
    if form.validate_on_submit():
        server.name = form.name.data
        server.ip_address = form.ip_address.data
        server.username = form.username.data
        server.password = form.password.data
        server.wireguard_address = form.wireguard_address.data
        db.session.commit()
        flash('Server information has been updated!', 'success')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.name.data = server.name
        form.ip_address.data = server.ip_address
        form.username.data = server.username
        form.password.data = server.password
        form.wireguard_address.data = server.wireguard_address
    return render_template('add_server.html', title='Edit Server', form=form)

@app.route('/delete_server/<int:server_id>', methods=['POST'])
@login_required
def delete_server(server_id):
    server = Server.query.get_or_404(server_id)
    db.session.delete(server)
    db.session.commit()
    flash('Server has been deleted!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/add_wg_connection/<int:server_id>', methods=['GET', 'POST'])
@login_required
def add_wg_connection(server_id):
    server = Server.query.get_or_404(server_id)
    form = AddWGConnectionForm()
    form.router_id.choices = [(router.id, router.name) for router in Router.query.all()]
    
    if form.validate_on_submit():
        router = Router.query.get_or_404(form.router_id.data)
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(server.ip_address, username=server.username, password=server.password)

            client_private_key = run_remote_command(client, "wg genkey").strip()
            client_public_key = run_remote_command(client, f"echo {client_private_key} | wg pubkey").strip()

            next_ip = find_next_available_ip(server)
            if not next_ip:
                flash('No available IP address in the WireGuard subnet.', 'danger')
                return redirect(url_for('dashboard'))

            wg_config = f"""[Peer]
PublicKey = {client_public_key}
AllowedIPs = {next_ip}/32
"""
            run_remote_command(client, f'echo "{wg_config}" | sudo tee -a /etc/wireguard/wg0.conf')
            run_remote_command(client, f"sudo wg set wg0 peer {client_public_key} allowed-ips {next_ip}/32")
            run_remote_command(client, "sudo systemctl restart wg-quick@wg0")

            wg_connection = WireGuardConnection(
                connection_name=form.connection_name.data,
                server_id=server.id,
                router_id=router.id,
                client_private_key=client_private_key,
                client_public_key=client_public_key,
                client_ip=next_ip
            )
            db.session.add(wg_connection)
            db.session.commit()

            client.close()

            flash('WireGuard connection has been added!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f"Error during WireGuard connection creation: {e}", 'danger')

    return render_template('add_wg_connection.html', title='Add WireGuard Connection', form=form, server=server)

@app.route('/manage_router/<int:router_id>', methods=['GET'])
@login_required
def manage_router(router_id):
    router = Router.query.get_or_404(router_id)
    return render_template('manage_router.html', router=router)

@app.route('/manage_server/<int:server_id>', methods=['GET'])
@login_required
def manage_server(server_id):
    server = Server.query.get_or_404(server_id)
    return render_template('manage_server.html', server=server)

@app.route('/manage_connections/<int:server_id>', methods=['GET'])
@login_required
def manage_connections(server_id):
    server = Server.query.get_or_404(server_id)
    connections = WireGuardConnection.query.filter_by(server_id=server.id).all()
    
    wg_show_output = fetch_wg_connections(server.ip_address, server.username, server.password)
    wg_connections = parse_wg_show_output(wg_show_output)

    return render_template('manage_connections.html', server=server, connections=connections, wg_connections=wg_connections)

@app.route('/ping_status/<string:ip_address>', methods=['GET'])
@login_required
def ping_status(ip_address):
    status = "offline"
    latency = "N/A"
    try:
        if platform.system().lower() == "windows":
            command = ["ping", "-n", "1", ip_address]
        else:
            command = ["ping", "-c", "1", ip_address]
        output = subprocess.check_output(command).decode()
        if "time=" in output:
            status = "online"
            latency = output.split("time=")[1].split(" ms")[0] + " ms"
    except Exception as e:
        logging.error(f"Ping failed: {e}")
    return jsonify({"status": status, "latency": latency})

@app.route('/ssh_status/<int:server_id>', methods=['GET'])
@login_required
def ssh_status(server_id):
    server = Server.query.get_or_404(server_id)
    status = check_ssh_connection(server.ip_address, server.username, server.password)
    return jsonify({"status": status})

@app.route('/config_wg/<int:server_id>', methods=['GET'])
@login_required
def config_wg(server_id):
    server = Server.query.get_or_404(server_id)
    
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(server.ip_address, username=server.username, password=server.password)

        steps = [
            ("sudo DEBIAN_FRONTEND=noninteractive apt-get update -y", 10),
            ("sudo DEBIAN_FRONTEND=noninteractive apt-get install wireguard -y", 20),
        ]

        for command, progress in steps:
            run_remote_command(client, command)
            socketio.emit('progress', {'progress': progress}, namespace='/config')

        server_private_key = run_remote_command(client, "wg genkey").strip()
        server_public_key = run_remote_command(client, f"echo {server_private_key} | wg pubkey").strip()
        socketio.emit('progress', {'progress': 40}, namespace='/config')

        network_interface = run_remote_command(client, "ip -o -4 route show to default | awk '{print $5}'").strip()
        socketio.emit('progress', {'progress': 60}, namespace='/config')

        server_config = f"""[Interface]
Address = {server.wireguard_address}
SaveConfig = true
ListenPort = 51820
PrivateKey = {server_private_key}
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {network_interface} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {network_interface} -j MASQUERADE
"""
        run_remote_command(client, f'echo "{server_config}" | sudo tee /etc/wireguard/wg0.conf')
        run_remote_command(client, "sudo chmod 600 /etc/wireguard/wg0.conf")
        run_remote_command(client, "echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf")
        run_remote_command(client, "sudo sysctl -p")
        run_remote_command(client, "sudo ufw allow 51820/udp")
        run_remote_command(client, "sudo systemctl enable wg-quick@wg0")
        run_remote_command(client, "sudo systemctl start wg-quick@wg0")

        socketio.emit('progress', {'progress': 100}, namespace='/config')

        server.wg_configured = True
        server.public_key = server_public_key  # Save the server public key in the database
        db.session.commit()

        client.close()

        flash(f'WireGuard has been configured for {server.name}', 'success')
    except Exception as e:
        flash(f"Error during WireGuard installation and configuration: {e}", 'danger')

    return redirect(url_for('dashboard'))

@app.route('/wg_connection_detail/<int:connection_id>', methods=['GET'])
@login_required
def wg_connection_detail(connection_id):
    connection = WireGuardConnection.query.get_or_404(connection_id)
    server = Server.query.get_or_404(connection.server_id)
    router = Router.query.get_or_404(connection.router_id)

    # Fetch the server public key directly from the Ubuntu server
    server_public_key = fetch_server_public_key(server.ip_address, server.username, server.password)
    if not server_public_key:
        flash('Failed to fetch server public key.', 'danger')
        return redirect(url_for('manage_connections', server_id=server.id))

    wg_config = f"""
[Interface]
PrivateKey = {connection.client_private_key}
Address = {connection.client_ip}/24

[Peer]
PublicKey = {server_public_key}
Endpoint = {server.ip_address}:51820
AllowedIPs = 128.0.0.0/1,0.0.0.0/1
"""

    # Fetch server IP information from ipinfo.io
    response = requests.get(f'https://ipinfo.io/{server.ip_address}/json')
    ip_info = response.json() if response.status_code == 200 else {}

    return render_template('wg_connection_detail.html', connection=connection, wg_config=wg_config, server=server, router=router, ip_info=ip_info)

@app.route('/setup_router/<int:connection_id>', methods=['POST'])
@login_required
def setup_router(connection_id):
    connection = WireGuardConnection.query.get_or_404(connection_id)
    router = Router.query.get_or_404(connection.router_id)
    server = Server.query.get_or_404(connection.server_id)

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(router.ip_address, username=router.username, password=router.password)

        commands = [
            f'/interface wireguard add name={connection.connection_name} private-key="{connection.client_private_key}"',
            f'/interface wireguard peers add interface={connection.connection_name} public-key="{server.public_key}" endpoint-address={server.ip_address} endpoint-port=51820 allowed-address=128.0.0.0/1,0.0.0.0/1',
            f'/ip address add address={connection.client_ip}/24 interface={connection.connection_name}',
            f'/interface enable [find name={connection.connection_name}]'
        ]

        for command in commands:
            logging.info(f"Executing command on router: {command}")
            run_remote_command(client, command)

        client.close()
        flash('WireGuard connection has been set up in the router!', 'success')
    except Exception as e:
        flash(f"Error setting up WireGuard connection in the router: {e}", 'danger')

    return redirect(url_for('wg_connection_detail', connection_id=connection_id))

@app.route('/delete_wg_connection/<int:connection_id>', methods=['POST'])
@login_required
def delete_wg_connection(connection_id):
    connection = WireGuardConnection.query.get_or_404(connection_id)
    db.session.delete(connection)
    db.session.commit()
    flash('WireGuard connection has been deleted!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete_wg_server_connection', methods=['POST'])
@login_required
def delete_wg_server_connection():
    peer = request.form.get('peer')
    server_id = request.form.get('server_id')
    server = Server.query.get_or_404(server_id)

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(server.ip_address, username=server.username, password=server.password)
        
        run_remote_command(client, f"sudo wg set wg0 peer {peer} remove")
        run_remote_command(client, "sudo systemctl restart wg-quick@wg0")
        
        client.close()
        flash('WireGuard connection has been deleted from the server!', 'success')
    except Exception as e:
        flash(f"Error deleting WireGuard connection from the server: {e}", 'danger')

    return redirect(url_for('manage_connections', server_id=server_id))

if __name__ == "__main__":
    socketio.run(app)

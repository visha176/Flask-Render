from app import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

class Router(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    wireguard_address = db.Column(db.String(100), nullable=False)
    public_key = db.Column(db.String(100), nullable=True)  # Add this line
    wg_configured = db.Column(db.Boolean, default=False)


class WireGuardConnection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    connection_name = db.Column(db.String(100), nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=False)
    router_id = db.Column(db.Integer, db.ForeignKey('router.id'), nullable=False)
    client_private_key = db.Column(db.String(255), nullable=False)
    client_public_key = db.Column(db.String(255), nullable=False)
    client_ip = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"<WireGuardConnection {self.connection_name}>"

    @property
    def config(self):
        # Replace with actual logic to generate or fetch the WireGuard configuration
        return f"[Interface]\nPrivateKey = {self.server.private_key}\nAddress = {self.server.wireguard_address}\n\n[Peer]\nPublicKey = {self.router.public_key}\nEndpoint = {self.router.ip_address}\nAllowedIPs = 0.0.0.0/0"


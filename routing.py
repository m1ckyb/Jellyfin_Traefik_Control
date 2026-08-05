import os
import subprocess
import paramiko
import tempfile
import database as db
import time
import shlex

def get_routing_mode(service=None):
    if service and service.get('routing_mode'):
        return service['routing_mode']
    return db.get_setting('ROUTING_MODE', 'unifi')

class WireGuardManager:
    @staticmethod
    def create_config():
        """Creates the wg0.conf file from settings."""
        # Helper to validate/sanitize input before writing to file
        # Config file format doesn't use shell quoting, but we should ensure no newlines
        # or weird characters inject extra config lines.
        
        def clean(value):
            if not value: return ""
            return value.replace('\n', '').replace('\r', '').strip()

        private_key = clean(db.get_setting('WG_PRIVATE_KEY'))
        address = clean(db.get_setting('WG_CLIENT_ADDRESS'))
        peer_public_key = clean(db.get_setting('WG_SERVER_PUBLIC_KEY'))
        endpoint = clean(db.get_setting('WG_SERVER_ENDPOINT'))
        allowed_ips = clean(db.get_setting('WG_ALLOWED_IPS', '0.0.0.0/0'))
        
        if not all([private_key, address, peer_public_key, endpoint]):
            return False, "Missing WireGuard configuration"

        # Basic validation to prevent config injection
        # Address should be CIDR
        # Endpoint should be IP:Port
        # Keys should be base64-ish
        
        # We write to a file, so command injection isn't the risk here, 
        # but config injection is.
        
        config_content = f"""[Interface]
PrivateKey = {private_key}
Address = {address}

[Peer]
PublicKey = {peer_public_key}
Endpoint = {endpoint}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""
        config_dir = '/etc/wireguard'
        config_path = os.path.join(config_dir, 'wg0.conf')
        try:
            os.makedirs(config_dir, exist_ok=True)
            with open(config_path, 'w') as f:
                f.write(config_content)
            os.chmod(config_path, 0o600)
            return True, config_path
        except Exception as e:
            return False, str(e)

    @staticmethod
    def up():
        """Brings up the WireGuard interface."""
        # Check if already up
        try:
            subprocess.check_call(['ip', 'link', 'show', 'wg0'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True, "Already up"
        except subprocess.CalledProcessError:
            pass # Interface doesn't exist

        success, msg = WireGuardManager.create_config()
        if not success:
            return False, msg

        try:
            # wg-quick up might fail if it tries to set sysctls that are locked in docker
            # But usually it works if NET_ADMIN is there.
            subprocess.check_call(['wg-quick', 'up', 'wg0'])
            return True, "Interface up"
        except subprocess.CalledProcessError as e:
            return False, f"wg-quick up failed: {e}"

    @staticmethod
    def down():
        """Brings down the WireGuard interface."""
        try:
            subprocess.check_call(['wg-quick', 'down', 'wg0'])
            return True, "Interface down"
        except subprocess.CalledProcessError:
             # Try to clean up anyway if wg-quick fails (e.g. interface gone)
            try:
                subprocess.check_call(['ip', 'link', 'del', 'wg0'])
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
            return True, "Interface down (or already down)"

class VPSManager:
    @staticmethod
    def get_ssh_client(timeout=5):
        host = db.get_setting('VPS_HOST')
        user = db.get_setting('VPS_SSH_USER', 'root')
        try:
            port = int(db.get_setting('VPS_SSH_PORT', '22'))
        except (ValueError, TypeError):
            port = 22
        key_content = db.get_setting('VPS_SSH_KEY')

        if not all([host, user, key_content]):
            raise Exception("Missing VPS SSH configuration")

        # Normalize key content (ensure it has newlines)
        key_content = key_content.strip()
        
        # Create a temp file for the key
        key_file = tempfile.NamedTemporaryFile(delete=False)
        key_file.write(key_content.encode())
        key_file.close()
        
        try:
            # Try to load as RSA, then others if needed
            try:
                k = paramiko.RSAKey.from_private_key_file(key_file.name)
            except paramiko.SSHException:
                k = None

            client = paramiko.SSHClient()
            # Use system known_hosts for host key verification
            known_hosts_path = os.path.expanduser('~/.ssh/known_hosts')
            if os.path.exists(known_hosts_path):
                client.load_system_host_keys(known_hosts_path)
            # Fall back to WarningPolicy if no known_hosts file exists
            client.set_missing_host_key_policy(paramiko.WarningPolicy())
            
            if k:
                client.connect(host, port=port, username=user, pkey=k, timeout=timeout)
            else:
                client.connect(host, port=port, username=user, key_filename=key_file.name, timeout=timeout)
                
            # Trust-On-First-Use (TOFU) host key verification
            try:
                remote_key = client.get_transport().get_remote_server_key()
                import binascii
                fingerprint = binascii.hexlify(remote_key.get_fingerprint()).decode()
                stored_fingerprint = db.get_setting("VPS_SSH_HOST_KEY")
                if stored_fingerprint:
                    if fingerprint != stored_fingerprint:
                        client.close()
                        raise Exception(f"Host key verification failed! Host key has changed. Stored: {stored_fingerprint}, Server: {fingerprint}")
                else:
                    db.set_setting("VPS_SSH_HOST_KEY", fingerprint)
            except Exception as ex:
                if "Host key verification failed" in str(ex):
                    raise
                pass
                
            return client
        finally:
            os.unlink(key_file.name)

    @staticmethod
    def forward_port(public_port, local_ip, local_port):
        """
        Adds iptables rule on VPS to forward traffic.
        iptables -t nat -A PREROUTING -p tcp --dport <public_port> -j DNAT --to-destination <local_ip>:<local_port>
        """
        client = VPSManager.get_ssh_client()
        
        # Sanitization
        s_public_port = shlex.quote(str(public_port))
        s_local_ip = shlex.quote(str(local_ip))
        s_local_port = shlex.quote(str(local_port))

        # Clean up existing rule for this port first
        VPSManager.cleanup_port_forward(public_port, client=client)

        cmds = []
        
        # Check Masquerade
        check_masq = "iptables -t nat -C POSTROUTING -j MASQUERADE"
        stdin, stdout, stderr = client.exec_command(check_masq)
        if stdout.channel.recv_exit_status() != 0:
            cmds.append("iptables -t nat -A POSTROUTING -j MASQUERADE")

        # Add DNAT
        # We quote the arguments to prevent injection
        cmds.append(f"iptables -t nat -A PREROUTING -p tcp --dport {s_public_port} -j DNAT --to-destination {s_local_ip}:{s_local_port}")
        
        for cmd in cmds:
            stdin, stdout, stderr = client.exec_command(cmd)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status != 0:
                error = stderr.read().decode()
                client.close()
                raise Exception(f"VPS command failed: {cmd} -> {error}")
        
        client.close()
        return True

    @staticmethod
    def cleanup_port_forward(public_port, client=None):
        should_close = False
        if not client:
            try:
                client = VPSManager.get_ssh_client()
                should_close = True
            except Exception:
                return

        # Sanitization
        s_public_port = shlex.quote(str(public_port))

        # Find rules matching --dport {public_port}
        # We rely on grep to find the line, but we must ensure grep pattern is safe.
        # shlex.quote handles this.
        stdin, stdout, stderr = client.exec_command(f"iptables-save | grep 'dport {s_public_port}'")
        rules = stdout.read().decode().splitlines()
        
        for rule in rules:
            if "-A " in rule and "DNAT" in rule:
                # Convert Add rule to Delete rule
                import re
                del_cmd = rule.replace("-A ", "-D ").strip()
                cmd = f"iptables -t nat {del_cmd}"
                # Ensure the command only contains standard characters and conforms to a standard iptables DNAT structure
                if re.match(r"^iptables -t nat -D [A-Z_]+ -p tcp( -m tcp)? --dport \d+ -j DNAT --to-destination [\d\.:]+$", cmd):
                    client.exec_command(cmd)
        
        if should_close:
            client.close()

    @staticmethod
    def test_connection(host, user, port, key_content):
        key_file = tempfile.NamedTemporaryFile(delete=False)
        key_file.write(key_content.encode())
        key_file.close()
        try:
            client = paramiko.SSHClient()
            # Use system known_hosts for host key verification
            known_hosts_path = os.path.expanduser('~/.ssh/known_hosts')
            if os.path.exists(known_hosts_path):
                client.load_system_host_keys(known_hosts_path)
            client.set_missing_host_key_policy(paramiko.WarningPolicy())
            client.connect(host, port=int(port), username=user, key_filename=key_file.name, timeout=5)
            
            # Trust-On-First-Use (TOFU) host key verification
            try:
                remote_key = client.get_transport().get_remote_server_key()
                import binascii
                fingerprint = binascii.hexlify(remote_key.get_fingerprint()).decode()
                stored_fingerprint = db.get_setting("VPS_SSH_HOST_KEY")
                if stored_fingerprint:
                    if fingerprint != stored_fingerprint:
                        client.close()
                        return False, f"Host key verification failed! Host key has changed. Stored: {stored_fingerprint}, Server: {fingerprint}"
                else:
                    db.set_setting("VPS_SSH_HOST_KEY", fingerprint)
            except Exception as ex:
                if "Host key verification failed" in str(ex):
                    client.close()
                    return False, str(ex)
            
            client.close()
            return True, "Connection successful"
        except Exception as e:
            return False, str(e)
        finally:
            os.unlink(key_file.name)

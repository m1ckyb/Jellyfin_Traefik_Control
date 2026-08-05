import json
import threading
import paho.mqtt.client as mqtt
import database as db

class MQTTHandler:
    def __init__(self, command_callback=None):
        self.client = None
        self.enabled = False
        self.host = None
        self.port = 1883
        self.username = None
        self.password = None
        self.discovery_prefix = "homeassistant"
        self.command_callback = command_callback
        self.running = False
        self._lock = threading.RLock()

    def load_config(self):
        """Load MQTT configuration from database."""
        self.enabled = db.get_setting("MQTT_ENABLED", "0") == "1"
        self.host = db.get_setting("MQTT_HOST")
        self.port = int(db.get_setting("MQTT_PORT", "1883"))
        self.username = db.get_setting("MQTT_USER")
        self.password = db.get_setting("MQTT_PASS")
        self.discovery_prefix = db.get_setting("MQTT_DISCOVERY_PREFIX", "homeassistant")

    def start(self):
        """Start the MQTT client if enabled."""
        with self._lock:
            self.load_config()
            
            if not self.enabled:
                if self.running:
                    self.stop()
                return

            if not self.host:
                print("⚠️ MQTT enabled but no host configured.")
                return

            if self.running:
                # If already running, we might need to reconnect if config changed
                # For simplicity, we can restart
                self.stop()

            try:
                self.client = mqtt.Client()
                if self.username:
                    self.client.username_pw_set(self.username, self.password)
                
                self.client.on_connect = self.on_connect
                self.client.on_message = self.on_message
                self.client.on_disconnect = self.on_disconnect

                print(f"🔹 Connecting to MQTT Broker at {self.host}:{self.port}...")
                self.client.connect_async(self.host, self.port, 60)
                self.client.loop_start()
                self.running = True
                
            except Exception as e:
                print(f"❌ Failed to start MQTT client: {e}")
                self.running = False

    def stop(self):
        """Stop the MQTT client."""
        with self._lock:
            if self.client:
                print("🔹 Stopping MQTT client...")
                try:
                    self.remove_global_discovery()
                except Exception:
                    pass
                self.client.loop_stop()
                self.client.disconnect()
                self.client = None
            self.running = False

    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            print("✅ Connected to MQTT Broker")
            self.publish_all_discovery()
            # Subscribe to all service command topics
            self.subscribe_all()
        else:
            print(f"❌ MQTT Connection failed with code {rc}")

    def on_disconnect(self, client, userdata, rc):
        if rc != 0:
            print("⚠️ MQTT Unexpected disconnection. Auto-reconnect should handle this.")
        else:
            print("🔹 MQTT Disconnected")

    def on_message(self, client, userdata, msg):
        try:
            parts = msg.topic.split('/')
            if len(parts) >= 3 and parts[0] == "routeghost":
                payload = msg.payload.decode().upper()
                
                # Service commands: routeghost/service/<service_id>/set
                if len(parts) >= 4 and parts[1] == "service" and parts[3] == "set":
                    service_id = int(parts[2])
                    if self.command_callback:
                        if payload == "ON":
                            print(f"🔹 MQTT Command: Turn ON Service {service_id}")
                            self.command_callback(service_id, "ON")
                        elif payload == "OFF":
                            print(f"🔹 MQTT Command: Turn OFF Service {service_id}")
                            self.command_callback(service_id, "OFF")
                        elif payload == "ROTATE":
                            print(f"🔹 MQTT Command: Rotate Service {service_id}")
                            self.command_callback(service_id, "ROTATE")
                
                # Global commands: routeghost/global/set
                elif parts[1] == "global" and parts[2] == "set":
                    if self.command_callback:
                        if payload in ["ALL_ON", "ALL_OFF", "ROTATE_PORT"]:
                            print(f"🔹 MQTT Global Command: {payload}")
                            self.command_callback("global", payload)

        except Exception as e:
            print(f"❌ Error handling MQTT message: {e}")

    def subscribe_all(self):
        """Subscribe to command topics for all services and global commands."""
        if not self.client or not self.client.is_connected():
            return
            
        # Subscribe to global commands
        self.client.subscribe("routeghost/global/set")

        # Subscribe to service commands
        services = db.get_all_services()
        for service in services:
            topic = f"routeghost/service/{service['id']}/set"
            self.client.subscribe(topic)

    def publish_discovery(self, service):
        """Publish Home Assistant Discovery config for a service."""
        if not self.client or not self.client.is_connected():
            return

        service_id = service['id']
        unique_id = f"routeghost_service_{service_id}"
        
        # 1. Switch for Service Control
        topic = f"{self.discovery_prefix}/switch/routeghost/{service_id}/config"
        
        payload = {
            "name": f"RouteGhost {service['name']}",
            "unique_id": unique_id,
            "command_topic": f"routeghost/service/{service_id}/set",
            "state_topic": f"routeghost/service/{service_id}/state",
            "json_attributes_topic": f"routeghost/service/{service_id}/attributes",
            "availability_topic": "routeghost/status",
            "device": {
                "identifiers": ["routeghost_main"],
                "name": "RouteGhost Manager",
                "manufacturer": "RouteGhost",
                "model": "RouteGhost Gateway",
                "sw_version": "0.1.1" 
            }
        }
        
        self.client.publish(topic, json.dumps(payload), retain=True)

        # 2. Button for URL Rotation
        rotate_topic = f"{self.discovery_prefix}/button/routeghost/{service_id}_rotate/config"
        rotate_payload = {
            "name": f"Rotate {service['name']} URL",
            "unique_id": f"{unique_id}_rotate",
            "command_topic": f"routeghost/service/{service_id}/set",
            "payload_press": "ROTATE",
            "icon": "mdi:refresh",
            "availability_topic": "routeghost/status",
            "device": {
                "identifiers": ["routeghost_main"]
            }
        }
        self.client.publish(rotate_topic, json.dumps(rotate_payload), retain=True)
        
        # Publish current state and attributes immediately
        is_active = service['enabled'] == 1
        self.publish_state(service, is_active)

    def publish_global_discovery(self):
        """Publish discovery for global buttons (Rotate Port, All On, All Off)."""
        if not self.client or not self.client.is_connected():
            return

        # 1. Rotate Port Button
        rotate_port_topic = f"{self.discovery_prefix}/button/routeghost/rotate_port/config"
        rotate_port_payload = {
            "name": "Rotate Firewall Port",
            "unique_id": "routeghost_rotate_port",
            "command_topic": "routeghost/global/set",
            "payload_press": "ROTATE_PORT",
            "icon": "mdi:shield-sync",
            "availability_topic": "routeghost/status",
            "device": {
                "identifiers": ["routeghost_main"],
                "name": "RouteGhost Manager",
                "manufacturer": "RouteGhost",
                "model": "RouteGhost Gateway",
                "sw_version": "0.1.1"
            }
        }
        self.client.publish(rotate_port_topic, json.dumps(rotate_port_payload), retain=True)

        # 2. All On Button
        all_on_topic = f"{self.discovery_prefix}/button/routeghost/all_on/config"
        all_on_payload = {
            "name": "Turn All Services ON",
            "unique_id": "routeghost_all_on",
            "command_topic": "routeghost/global/set",
            "payload_press": "ALL_ON",
            "icon": "mdi:play-all",
            "availability_topic": "routeghost/status",
            "device": { "identifiers": ["routeghost_main"] }
        }
        self.client.publish(all_on_topic, json.dumps(all_on_payload), retain=True)

        # 3. All Off Button
        all_off_topic = f"{self.discovery_prefix}/button/routeghost/all_off/config"
        all_off_payload = {
            "name": "Turn All Services OFF",
            "unique_id": "routeghost_all_off",
            "command_topic": "routeghost/global/set",
            "payload_press": "ALL_OFF",
            "icon": "mdi:stop-all",
            "availability_topic": "routeghost/status",
            "device": { "identifiers": ["routeghost_main"] }
        }
        self.client.publish(all_off_topic, json.dumps(all_off_payload), retain=True)

    def publish_all_discovery(self):
        """Publish discovery for all services and availability."""
        if not self.client or not self.client.is_connected():
            return
            
        # Publish availability
        self.client.publish("routeghost/status", "online", retain=True)
        
        # Global buttons
        self.publish_global_discovery()
        
        services = db.get_all_services()
        for service in services:
            self.publish_discovery(service)

    def remove_discovery(self, service_id):
        """Remove Home Assistant Discovery config for a service."""
        if not self.client or not self.client.is_connected():
            return

        # Clear Switch
        topic = f"{self.discovery_prefix}/switch/routeghost/{service_id}/config"
        self.client.publish(topic, "", retain=True)

        # Clear Rotate Button
        rotate_topic = f"{self.discovery_prefix}/button/routeghost/{service_id}_rotate/config"
        self.client.publish(rotate_topic, "", retain=True)
        
        # Also clear state and attributes
        self.client.publish(f"routeghost/service/{service_id}/state", "", retain=True)
        self.client.publish(f"routeghost/service/{service_id}/attributes", "", retain=True)

    def remove_global_discovery(self):
        """Clear global button discovery."""
        if not self.client or not self.client.is_connected():
            return
            
        self.client.publish(f"{self.discovery_prefix}/button/routeghost/rotate_port/config", "", retain=True)
        self.client.publish(f"{self.discovery_prefix}/button/routeghost/all_on/config", "", retain=True)
        self.client.publish(f"{self.discovery_prefix}/button/routeghost/all_off/config", "", retain=True)

    def publish_state(self, service_dict_or_id, is_active, healthy=None):
        """Publish state update and attributes for a service."""
        if not self.client or not self.client.is_connected():
            return

        if isinstance(service_dict_or_id, dict):
            service_id = service_dict_or_id['id']
            service = service_dict_or_id
        else:
            service_id = service_dict_or_id
            service = db.get_service(service_id)

        if not service:
            return

        # 1. Publish State
        topic = f"routeghost/service/{service_id}/state"
        state = "ON" if is_active else "OFF"
        self.client.publish(topic, state, retain=True)

        # 2. Publish Attributes
        attr_topic = f"routeghost/service/{service_id}/attributes"
        
        current_url = "N/A"
        if service.get('current_hostname'):
            hostname = service['current_hostname']
            # We omit the port because Cloudflare/VPS handles the rewrite to standard 443/80
            if service.get('current_port') == 80:
                current_url = f"http://{hostname}"
            else:
                current_url = f"https://{hostname}"

        routing_mode = service.get('routing_mode', 'unifi')
        routing_label = "VPS Gateway" if routing_mode == 'vps' else "Cloudflare"

        attributes = {
            "routing_mode": routing_label,
            "router": service.get('router_name', 'N/A'),
            "service": service.get('service_name', 'N/A'),
            "target": service.get('target_url', 'N/A'),
            "prefix": service.get('subdomain_prefix', 'N/A'),
            "current_url": current_url,
            "health": "Healthy" if (healthy if healthy is not None else True) else "Unhealthy"
        }
        
        self.client.publish(attr_topic, json.dumps(attributes), retain=True)

    def reload(self):
        """Reload configuration and restart."""
        self.start()

# Global instance
mqtt_manager = MQTTHandler()

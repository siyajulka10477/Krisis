from __future__ import annotations

from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from uuid import uuid4
import json
import os
import threading
import time
import urllib.request

from app.models import DetectionEvent, EventEnvelope, Incident, ManualEvent, Notification, SensorEvent, StaffContact


class IncidentEngine:
    def __init__(self) -> None:
        self.events: deque[EventEnvelope] = deque(maxlen=500)
        self.active_incidents: dict[str, Incident] = {}
        self.location_windows: dict[str, deque[EventEnvelope]] = defaultdict(lambda: deque(maxlen=100))
        self.staff_directory = self._build_staff_directory()
        self._init_staff_positions()
        self.notifications: deque[Notification] = deque(maxlen=300)
        self.notifications_by_incident: dict[str, list[str]] = defaultdict(list)
        self.persistence_window = timedelta(seconds=15)
        self.min_fire_hits = 1
        self.min_smoke_hits = 1
        self.temp_threshold = 58.0
        self.gas_threshold = 70.0
        self.sound_threshold = 85.0
        
        # Auto-resolution settings
        self.resolution_timeout = timedelta(seconds=30)
        self._janitor_thread = threading.Thread(target=self._janitor_loop, daemon=True)
        self._janitor_thread.start()

    def _janitor_loop(self) -> None:
        """Background thread that re-evaluates incidents every 30s to auto-clear resolved threats."""
        while True:
            try:
                time.sleep(30)
                locations = list(self.active_incidents.keys())
                for loc in locations:
                    incident = self.active_incidents.get(loc)
                    if not incident:
                        continue
                    
                    # CRITICAL: Manually trim the window since no new events are arriving to trigger it
                    window = self.location_windows[loc]
                    self._trim_window(window)
                        
                    # Re-evaluate the trimmed window
                    evaluation = self._recompute_for_location(loc)
                    
                    # Manual incidents (Panic button) have special persistence rules
                    # But we follow the user request: persist until MANUAL resolution
                    pass
            except Exception as e:
                print(f"[engine] Janitor error: {e}")
            except Exception as e:
                print(f"[engine] Janitor error: {e}")

    def add_detection(self, event: DetectionEvent) -> Incident | None:
        stamped = event.with_updates(timestamp=event.timestamp or self._now())
        envelope = EventEnvelope(kind="detection", payload=stamped, received_at=self._now())
        self._push(stamped.location, envelope)
        return self._recompute_for_location(stamped.location)

    def add_sensor(self, event: SensorEvent) -> Incident | None:
        stamped = event.with_updates(timestamp=event.timestamp or self._now())
        envelope = EventEnvelope(kind="sensor", payload=stamped, received_at=self._now())
        self._push(stamped.location, envelope)
        return self._recompute_for_location(stamped.location)

    def add_manual(self, stamped: ManualEvent) -> Incident:
        envelope = EventEnvelope(
            kind="manual",
            received_at=self._now(),
            payload=stamped.to_dict(),
        )
        self.events.append(envelope)
        self._push(stamped.location, envelope)

        # Handle SOS Portal Triggers
        is_sos = stamped.source == "sos_portal"
        is_update = stamped.notes and "LOCATION UPDATE" in stamped.notes
        trigger = stamped.trigger_type.lower()
        
        itype: IncidentType = "security"
        if "fire" in trigger: itype = "fire"
        elif "medical" in trigger: itype = "medical"
        elif "security" in trigger: itype = "security"
        elif "panic" in trigger: itype = "security"
        
        summary = f"SOS Alert from {stamped.location}"
        logical_location = stamped.location
        
        if is_sos:
            summary = f"Emergency {itype.upper()} Signal from {stamped.location}"
            if is_update:
                # Extract floor/area if possible for smarter routing
                # Format: "LOCATION UPDATE: Floor 1 | Area: Rooms 101-105"
                summary = f"{itype.upper()} | {stamped.notes}"
                
                # Attempt to extract a better routing location
                if "Floor" in stamped.notes:
                    for floor in ["Floor 1", "Floor 2", "Floor 3", "Basement", "Ground", "Rooftop"]:
                        if floor in stamped.notes:
                            logical_location = floor
                            break

        # For SOS alerts, we use the trigger_id as the key.
        # If it's a LOCATION UPDATE, we attempt to find an existing active incident for "Mobile Staff"
        # to ensure updates collapse into the same card.
        incident_key = f"manual-{stamped.trigger_id}" if is_sos else stamped.location
        
        if is_sos and is_update:
            for k, inc in self.active_incidents.items():
                if inc.location == "Mobile Staff" and inc.source == "manual":
                    incident_key = k
                    break

        return self._upsert_incident(
            location=stamped.location,
            incident_type=itype,
            severity="critical",
            summary=summary,
            recommended_action="Dispatch immediate response team. Call location to verify status.",
            evidence=[f"source:{stamped.source}", f"trigger:{stamped.trigger_id}"],
            source="manual",
            key=incident_key
        ).with_updates(location=logical_location) if is_update else self._upsert_incident(
            location=stamped.location,
            incident_type=itype,
            severity="critical",
            summary=summary,
            recommended_action="Dispatch immediate response team. Call location to verify status.",
            evidence=[f"source:{stamped.source}", f"trigger:{stamped.trigger_id}"],
            source="manual",
            key=incident_key
        )

    def add_broadcast(self, message: str) -> Incident:
        return self._upsert_incident(
            location="All Zones",
            incident_type="broadcast",
            severity="medium",
            summary="System Broadcast",
            recommended_action=message,
            evidence=["manual:broadcast"],
            source="manual",
        )

    def _init_staff_positions(self) -> None:
        now = self._now().isoformat()
        for s in self.staff_directory:
            # HQ staff are at Command Center, others at their duty zone
            s.current_zone = "Command Center" if "hq" in s.contact_id.lower() else s.zone
            s.last_seen = now

    def update_staff_location(self, contact_id: str, zone: str) -> bool:
        for s in self.staff_directory:
            if s.contact_id == contact_id:
                s.current_zone = zone
                s.last_seen = self._now().isoformat()
                print(f"[engine] Staff {s.name} tracked at {zone}")
                return True
        return False

    def get_active_incidents(self) -> list[Incident]:
        return sorted(self.active_incidents.values(), key=lambda item: item.last_updated, reverse=True)

    def get_recent_events(self) -> list[EventEnvelope]:
        return list(self.events)[::-1]

    def resolve_incident(self, identifier: str) -> bool:
        # 1. Try to resolve by exact internal dictionary key
        if identifier in self.active_incidents:
            print(f"[engine] Resolving incident by key: {identifier}")
            del self.active_incidents[identifier]
            return True
            
        # 2. Try to resolve by incident_id (Short UUID)
        for key, incident in list(self.active_incidents.items()):
            if incident.incident_id == identifier:
                print(f"[engine] Resolving incident by ID: {identifier}")
                del self.active_incidents[key]
                # Also clear the window if the key matches the location
                if key in self.location_windows:
                    self.location_windows[key].clear()
                return True
                
        # 3. Fallback to location (clears the first incident found at this location)
        for key, incident in list(self.active_incidents.items()):
            if incident.location == identifier:
                print(f"[engine] Resolving incident at location fallback: {identifier}")
                del self.active_incidents[key]
                if identifier in self.location_windows:
                    self.location_windows[identifier].clear()
                return True
                
        return False

    def update_staff_location(self, contact_id: str, zone: str) -> bool:
        for s in self.staff_directory:
            if s.contact_id == contact_id:
                s.current_zone = zone
                s.last_seen = self._now().isoformat()
                print(f"[engine] Staff {s.name} tracked at {zone}")
                return True
        return False

    def get_staff_directory(self) -> list[StaffContact]:
        return list(self.staff_directory)

    def update_staff_directory(self, contacts: list[StaffContact]) -> None:
        self.staff_directory = contacts

    def get_notifications(self) -> list[Notification]:
        return list(self.notifications)[::-1]

    def acknowledge_notification(self, notification_id: str) -> Notification:
        for index, notification in enumerate(self.notifications):
            if notification.notification_id != notification_id:
                continue
            now = self._now()
            updated = notification.with_updates(
                status="acknowledged",
                updated_at=now,
                acknowledged_at=now,
            )
            self.notifications[index] = updated
            return updated
        raise KeyError(notification_id)

    def _push(self, location: str, envelope: EventEnvelope) -> None:
        self.events.append(envelope)
        window = self.location_windows[location]
        window.append(envelope)
        self._trim_window(window)

    def _trim_window(self, window: deque[EventEnvelope]) -> None:
        cutoff = self._now() - self.persistence_window
        while window and window[0].received_at < cutoff:
            window.popleft()

    def _recompute_for_location(self, location: str) -> Incident | None:
        window = self.location_windows[location]
        fire_hits = 0
        smoke_hits = 0
        abnormal_motion = 0
        crowd_panic = 0
        high_temp = False
        gas_alert = False
        loud_sound = False
        cameras: set[str] = set()
        sensors: set[str] = set()

        for entry in window:
            payload = entry.payload
            if entry.kind == "detection" and isinstance(payload, DetectionEvent):
                cameras.add(payload.camera_id)
                if payload.label == "fire" and payload.confidence >= 0.45:
                    fire_hits += 1
                elif payload.label == "smoke" and payload.confidence >= 0.40:
                    smoke_hits += 1
                elif payload.label == "abnormal_motion":
                    abnormal_motion += 1
                elif payload.label == "crowd_panic":
                    crowd_panic += 1
            elif entry.kind == "sensor" and isinstance(payload, SensorEvent):
                sensors.add(payload.sensor_id)
                if payload.sensor_type == "temperature" and payload.value >= self.temp_threshold:
                    high_temp = True
                elif payload.sensor_type == "gas" and payload.value >= self.gas_threshold:
                    gas_alert = True
                elif payload.sensor_type == "sound" and payload.value >= self.sound_threshold:
                    loud_sound = True

        if fire_hits >= self.min_fire_hits:
            severity = "critical" if (gas_alert or high_temp) else "high"
            return self._upsert_incident(
                location=location,
                incident_type="fire",
                severity=severity,
                summary="Confirmed fire pattern detected from camera and supporting signals.",
                recommended_action="Alert staff, isolate the zone, and begin evacuation guidance.",
                evidence=self._build_evidence(cameras, sensors, fire_hits, smoke_hits, high_temp, gas_alert),
            )

        if smoke_hits >= self.min_smoke_hits:
            return self._upsert_incident(
                location=location,
                incident_type="warning",
                severity="medium" if not high_temp else "high",
                summary="Smoke detected with enough persistence to trigger early warning.",
                recommended_action="Notify floor staff and verify the source immediately.",
                evidence=self._build_evidence(cameras, sensors, fire_hits, smoke_hits, high_temp, gas_alert),
            )

        if crowd_panic >= 2 or (abnormal_motion >= 3 and loud_sound):
            return self._upsert_incident(
                location=location,
                incident_type="security",
                severity="high",
                summary="Behavioral anomaly suggests possible security or crowd incident.",
                recommended_action="Dispatch security and pull live feeds for manual verification.",
                evidence=self._build_evidence(cameras, sensors, fire_hits, smoke_hits, high_temp, gas_alert),
            )

        return None

    def _build_evidence(
        self,
        cameras: set[str],
        sensors: set[str],
        fire_hits: int,
        smoke_hits: int,
        high_temp: bool,
        gas_alert: bool,
    ) -> list[str]:
        evidence = [f"cameras:{','.join(sorted(cameras))}" if cameras else "cameras:none"]
        evidence.append(f"sensors:{','.join(sorted(sensors))}" if sensors else "sensors:none")
        evidence.append(f"fire_hits:{fire_hits}")
        evidence.append(f"smoke_hits:{smoke_hits}")
        if high_temp:
            evidence.append("sensor:high_temperature")
        if gas_alert:
            evidence.append("sensor:gas_alert")
        return evidence

    def _upsert_incident(
        self,
        location: str,
        incident_type: str,
        severity: str,
        summary: str,
        recommended_action: str,
        evidence: list[str],
        source: Literal["ai", "manual"] = "ai",
        key: str | None = None,
    ) -> Incident:
        lookup_key = key or location
        existing = self.active_incidents.get(lookup_key)
        now = self._now()
        if existing:
            # Smart Prefix Merge: Replace tags with the same category prefix (e.g., "fire_hits:")
            # to prevent evidence list bloat while keeping unique tags.
            evidence_map = {}
            for tag in existing.evidence + evidence:
                if ":" in tag:
                    prefix = tag.split(":", 1)[0]
                    evidence_map[prefix] = tag
                else:
                    evidence_map[tag] = tag
            merged_evidence = list(evidence_map.values())

            updated = existing.with_updates(
                type=incident_type,
                severity=severity,
                summary=summary,
                recommended_action=recommended_action,
                last_updated=now,
                evidence=merged_evidence,
                source=source,
            )
            self.active_incidents[lookup_key] = updated
            self._sync_notifications(updated)
            return updated

        incident = Incident(
            incident_id=str(uuid4())[:8],
            type=incident_type,
            severity=severity,
            location=location,
            summary=summary,
            recommended_action=recommended_action,
            first_seen=now,
            last_updated=now,
            evidence=evidence,
            source=source,
        )
        self.active_incidents[lookup_key] = incident
        self._sync_notifications(incident)
        return incident

    def _now(self) -> datetime:
        return datetime.now(UTC)

    def _sync_notifications(self, incident: Incident) -> None:
        recipients = self._route_recipients(incident)
        existing_ids = set(self.notifications_by_incident.get(incident.incident_id, []))
        for contact, channel, reason in recipients:
            notification_id = f"{incident.incident_id}:{contact.contact_id}:{channel}"
            message = self._build_message(incident, contact, reason)
            if notification_id in existing_ids:
                self._update_notification(notification_id, incident, message, reason)
                continue

            now = self._now()
            status = "escalated" if contact.escalation_level >= 3 and incident.severity in {"high", "critical"} else "sent"
            notification = Notification(
                notification_id=notification_id,
                incident_id=incident.incident_id,
                location=incident.location,
                incident_type=incident.type,
                severity=incident.severity,
                recipient=contact,
                channel=channel,
                message=message,
                status=status,
                created_at=now,
                updated_at=now,
                reason=reason,
            )
            self.notifications.append(notification)
            self.notifications_by_incident[incident.incident_id].append(notification_id)
            self._dispatch_webhook(notification)

    def _update_notification(self, notification_id: str, incident: Incident, message: str, reason: str) -> None:
        for index, notification in enumerate(self.notifications):
            if notification.notification_id != notification_id:
                continue
            status = notification.status
            upgraded = False
            if status != "acknowledged" and incident.severity in {"high", "critical"} and notification.recipient.escalation_level >= 3:
                if status != "escalated":
                    upgraded = True
                status = "escalated"
            
            updated_notification = notification.with_updates(
                location=incident.location,
                incident_type=incident.type,
                severity=incident.severity,
                message=message,
                status=status,
                updated_at=self._now(),
                reason=reason,
            )
            self.notifications[index] = updated_notification
            
            if upgraded:
                self._dispatch_webhook(updated_notification)
            return

    def _dispatch_webhook(self, notification: Notification) -> None:
        def _send():
            endpoint = "/twilio/voice" if notification.channel == "voice" else "/twilio/sms"
            url = f"http://127.0.0.1:8090{endpoint}"
            payload = {
                "recipient": notification.recipient.phone,
                "message": notification.message
            }
            req = urllib.request.Request(
                url, 
                data=json.dumps(payload).encode("utf-8"), 
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            try:
                urllib.request.urlopen(req, timeout=3)
            except Exception:
                pass
                
        threading.Thread(target=_send, daemon=True).start()

    def send_real_whatsapp(self, to_phone: str, variables: dict[str, str] = None) -> None:
        """
        Actually connects to Twilio WhatsApp API using template HXb5b62575e6e4ff6129ad7c8efe1f983e.
        """
        if variables is None:
            now = self._now()
            variables = {
                "1": now.strftime("%d/%m"), 
                "2": now.strftime("%I%p").lower()
            }
            
        def _send():
            account_sid = os.getenv("TWILIO_ACCOUNT_SID")
            auth_token = os.getenv("TWILIO_AUTH_TOKEN")
            from_phone = "whatsapp:+14155238886"
            content_sid = "HXb5b62575e6e4ff6129ad7c8efe1f983e"
            
            # Normalize target phone
            target = to_phone.strip()
            if not target.startswith("whatsapp:"):
                target = f"whatsapp:{target}"
            if "whatsapp:+" not in target:
                target = target.replace("whatsapp:", "whatsapp:+")
            
            url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
            
            import urllib.parse
            data = {
                "To": target,
                "From": from_phone,
                "ContentSid": content_sid,
                "ContentVariables": json.dumps(variables)
            }
            encoded_data = urllib.parse.urlencode(data).encode("utf-8")
            
            import base64
            auth_str = f"{account_sid}:{auth_token}"
            encoded_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
            
            req = urllib.request.Request(
                url,
                data=encoded_data,
                headers={
                    "Authorization": f"Basic {encoded_auth}",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                method="POST"
            )
            
            try:
                with urllib.request.urlopen(req, timeout=10) as response:
                    print(f"[twilio] WhatsApp sent to {target}. Status: {response.status}")
            except Exception as e:
                print(f"[twilio] ERROR sending WhatsApp to {target}: {e}")
                
        threading.Thread(target=_send, daemon=True).start()

    def send_real_sms_direct(self, to_phone: str, message: str = None) -> None:
        """
        Actually connects to Twilio SMS API for standard text messages.
        """
        if message is None:
            message = f"CRITICAL ALERT: Emergency detected. Please check the Crisis Grid dashboard immediately."
            
        def _send():
            account_sid = os.getenv("TWILIO_ACCOUNT_SID")
            auth_token = os.getenv("TWILIO_AUTH_TOKEN")
            # Using the new SMS number from your screenshot
            from_phone = "+19893345858"
            
            # Normalize target phone
            target = to_phone.strip()
            if not target.startswith("+"):
                target = f"+{target}"
            
            url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
            
            import urllib.parse
            data = {
                "To": target,
                "From": from_phone,
                "Body": message
            }
            encoded_data = urllib.parse.urlencode(data).encode("utf-8")
            
            import base64
            auth_str = f"{account_sid}:{auth_token}"
            encoded_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
            
            req = urllib.request.Request(
                url,
                data=encoded_data,
                headers={
                    "Authorization": f"Basic {encoded_auth}",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                method="POST"
            )
            
            try:
                with urllib.request.urlopen(req, timeout=10) as response:
                    print(f"[twilio] SMS sent to {target}. Status: {response.status}")
            except Exception as e:
                print(f"[twilio] ERROR sending SMS to {target}: {e}")
                
        threading.Thread(target=_send, daemon=True).start()

    def send_manual_sms(self, phone: str, message: str) -> None:
        def _send():
            url = "http://127.0.0.1:8090/twilio/sms"
            payload = {
                "recipient": phone,
                "message": message
            }
            req = urllib.request.Request(
                url, 
                data=json.dumps(payload).encode("utf-8"), 
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            try:
                urllib.request.urlopen(req, timeout=3)
            except Exception:
                pass
                
        threading.Thread(target=_send, daemon=True).start()

    def _route_recipients(self, incident: Incident) -> list[tuple[StaffContact, str, str]]:
        recipients: list[tuple[StaffContact, str, str]] = []
        location_contacts = [
            contact for contact in self.staff_directory 
            if contact.on_shift and (
                incident.type == "broadcast" or 
                incident.location == "All Zones" or 
                contact.zone == incident.location or 
                contact.zone == "All Zones"
            )
        ]
        for contact in location_contacts:
            if incident.type == "warning" and contact.role not in {"Floor Manager", "Housekeeping Lead", "Security Lead"}:
                continue
            if incident.type == "medical" and contact.role not in {"Duty Manager", "Reception Head", "Security Lead"}:
                continue
            if incident.type == "security" and contact.role not in {"Security Lead", "Duty Manager", "Front Office Manager"}:
                continue

            channel = "sms"
            if "dashboard" in contact.channels and incident.severity == "medium":
                channel = "dashboard"
            elif "voice" in contact.channels and incident.severity == "critical":
                channel = "voice"
            recipients.append((contact, channel, self._reason_for_contact(incident, contact)))
        return recipients

    def _reason_for_contact(self, incident: Incident, contact: StaffContact) -> str:
        if contact.zone == incident.location:
            return "zone_owner"
        if contact.role == "Security Lead":
            return "security_escalation"
        if contact.role == "Duty Manager":
            return "command_escalation"
        return "operational_support"

    def _build_message(self, incident: Incident, contact: StaffContact, reason: str) -> str:
        return (
            f"{incident.type.upper()} | {incident.location} | {incident.severity.upper()} | "
            f"{incident.recommended_action} | Route: {contact.role} ({reason})"
        )

    def _build_staff_directory(self) -> list[StaffContact]:
        # Using consistent phone numbers for the demo
        phones = ["9893000445", "9425070640", "7000127676", "8889800445"]
        contacts = [
            # High Level Command (All Zones)
            ("hq-01", "Vikram Singh", "Head of Security", "All Zones", phones[0], ["sms", "voice", "dashboard"], 3),
            ("hq-02", "Sarah Chen", "Night Manager", "All Zones", phones[1], ["sms", "voice", "dashboard"], 3),
            ("hq-03", "Nidhi Rao", "Duty Manager", "All Zones", phones[2], ["sms", "voice", "dashboard"], 2),
            ("hq-04", "Sandeep Das", "Engineering Head", "All Zones", phones[3], ["dashboard", "sms"], 2),

            # Ground Floor Specialists
            ("gr-01", "Anita Verma", "Lobby Supervisor", "Ground", phones[0], ["sms", "dashboard"], 1),
            ("gr-02", "Chef Rajesh", "Kitchen Manager", "Ground", phones[1], ["sms", "dashboard"], 1),
            ("gr-03", "Karan Shah", "Reception Head", "Ground", phones[2], ["dashboard", "sms"], 1),

            # Floor Specific Wardens
            ("f1-01", "Rohit Jain", "Floor Warden", "Floor 1", phones[3], ["sms", "dashboard"], 1),
            ("f2-01", "Pooja Nair", "Floor Warden", "Floor 2", phones[0], ["sms", "dashboard"], 1),
            ("f3-01", "Amitabh K.", "Floor Warden", "Floor 3", phones[1], ["sms", "dashboard"], 1),

            # Specialized Zone Leads
            ("rt-01", "Ishita Bose", "Pool Attendant", "Rooftop", phones[2], ["sms", "dashboard"], 1),
            ("rt-02", "Marco Rossi", "Bar Manager", "Rooftop", phones[3], ["sms", "dashboard"], 1),
            ("bs-01", "Arjun Patel", "Maintenance Lead", "Basement", phones[0], ["sms", "dashboard"], 1),
            ("bs-02", "Suraj Mehra", "Parking Security", "Basement", phones[1], ["sms", "dashboard"], 1),
        ]
        return [
            StaffContact(
                contact_id=contact_id,
                name=name,
                role=role,
                zone=zone,
                phone=phone,
                channels=channels,
                escalation_level=level,
            )
            for contact_id, name, role, zone, phone, channels, level in contacts
        ]

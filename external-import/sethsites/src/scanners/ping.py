import re
import traceback
from datetime import datetime, timedelta
from threading import Event

import ciso8601
import pytz
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2.v21 import IPv4Address

from scanners import Scanner, SshScanner
from managers import IncidentManager, EnvironmentManager, RelationshipManager, MyIncident
from scalpl import Cut


class ScanTarget:
    def __init__(self, ip_address: str, start: datetime):
        self.ip_address: str = ip_address
        self.hits: int = 1
        self.start = start
        self.end = start


class Scan:
    def __init__(self, start: datetime, end: datetime, incident: MyIncident, fudge_time: timedelta):
        self.fudge_time: timedelta = fudge_time
        self.start_offset: datetime = start - fudge_time
        self.start: datetime = start
        self.end: datetime = end
        self.end_offset: datetime = end + fudge_time
        self.hits = 1
        self.targets: dict[str: ScanTarget] = {}
        self.incident = incident
        self.start_end_reset = False

    def setStartTime(self, start: datetime):
        self.start_offset = start - self.fudge_time
        self.start = start

    def setEndTime(self, end: datetime):
        self.end = end
        self.end_offset = end + self.fudge_time


class ScanHost:
    def __init__(self, ip_address: str):
        self.ip_address: str = ip_address
        self.id = None
        self.scans: [Scan] = []
        self.hits: int = 1


# The ping scanner uses icmp packets from zeek connection logs to identify ping scans.
# T1018
class PingScanner(Scanner):
    def __init__(self,
                 config: Cut,
                 env_manager: EnvironmentManager,
                 es: Elasticsearch,
                 helper: OpenCTIConnectorHelper,
                 incident_manager: IncidentManager,
                 relationship_manager: RelationshipManager,
                 ssh_scanner: SshScanner,
                 shutdown_event: Event):
        super(PingScanner, self).__init__(config, env_manager, es, helper,
                                          incident_manager, relationship_manager, shutdown_event)
        self.state_tracking_token = "ping_scanner_last_run"
        self.buffer = timedelta(seconds=float(self.config.get("scanner.ping.time_sensitivity", 300)))
        self.sensitivity = int(self.config.get("scanner.ping.target_sensitivity", 10))
        self.ssh_scanner = ssh_scanner

    def get_nmap_ssh_traffic_query(self, start: datetime, end: datetime) -> Search:
        s = Search(using=self.elasticsearch, index="filebeat*") \
            .filter("match", fileset__name="ssh") \
            .filter("wildcard", zeek__ssh__client="*Nmap*")
        s = self.add_exclude_ignored_networks_to_search(s)

        s.sort("zeek.ssh.ts")
        s.extra(track_total_hits=True)

        s = self.es_helper.set_time_range(s, "zeek.ssh.ts", start, end)

        return s

    def get_public_agg_query(self, start: datetime = None, end: datetime = None) -> Search:
        s = Search(using=self.elasticsearch, index="filebeat*") \
            .filter("match", network__transport="icmp") \
            .filter("match", zeek__connection__icmp__code="0") \
            .filter("match", zeek__connection__icmp__type="8") \
            .query("match", fileset__name="connection")
        for network in self.env_manager.public_networks:
            s = s.filter("match", source__ip=network)
        for host in self.env_manager.get_hosts_with_tag("ping master"):
            s = s.exclude("match", source__ip=host)
        s = self.add_exclude_ignored_networks_to_search(s)
        s = self.es_helper.set_time_range(s, "@timestamp", start, end)
        s.aggs.bucket("source", "terms", field="source.ip", size=999999) \
            .bucket("history", "date_histogram", field="@timestamp", fixed_interval="10m", min_doc_count=2)
        s.extra(track_total_hits=True)

        return s

    def get_private_agg_query(self, start: datetime = None, end: datetime = None) -> Search:
        interval = str(int(int(self.config.get("scanner.ping.time_sensitivity", 300))/60))+"m"
        query_objs = []
        for network in self.env_manager.private_networks:
            query_objs.append(Q("match", source__ip=network))
        q = Q('bool',
              should=query_objs,
              minimum_should_match=1)
        s = Search(using=self.elasticsearch, index="filebeat*") \
            .filter("match", network__transport="icmp") \
            .filter("match", zeek__connection__icmp__code="0") \
            .filter("match", zeek__connection__icmp__type="8") \
            .query("match", fileset__name="connection").query(q)
        for host in self.env_manager.get_hosts_with_tag("ping master"):
            s = s.exclude("match", source__ip=host)
        s = self.add_exclude_ignored_networks_to_search(s)
        s = self.es_helper.set_time_range(s, "@timestamp", start, end)
        s.aggs.bucket("source", "terms", field="source.ip", size=999999) \
            .bucket("history", "date_histogram", field="@timestamp", fixed_interval=interval,
                    min_doc_count=self.sensitivity)
        s.extra(track_total_hits=True)
        self.helper.log_info(f"{s.to_dict()}")

        return s

    def get_follow_up_query(self, ip_addr, start: datetime = None, end: datetime = None) -> Search:
        s = Search(using=self.elasticsearch, index="filebeat*") \
            .filter("match", network__transport="icmp") \
            .filter("match", zeek__connection__icmp__code="0") \
            .filter("match", zeek__connection__icmp__type="8") \
            .filter("match", fileset__name="connection") \
            .query("match", source__ip=ip_addr)

        s = self.es_helper.set_time_range(s, "@timestamp", start, end)
        s.aggs.bucket("destination", "terms", field="destination.ip", size=999999) \
              .metric("min_time", "min", field="@timestamp")\
            .metric("max_time", "max", field="@timestamp")
        s.extra(track_total_hits=True)

        return s

    def process_nmap_search(self, search: Search):
        search = search.params(scroll='120m')
        malicious_hosts: dict[str, ScanHost] = {}
        for hit in search.scan():
            ts = hit["@timestamp"]
            timestamp = ciso8601.parse_datetime(ts)

            if hit.source.ip in malicious_hosts:
                malicious_host = malicious_hosts[hit.source.ip]
                malicious_host.hits += 1
            else:
                malicious_host = ScanHost(hit.source.ip)
                malicious_hosts[hit.source.ip] = malicious_host

            current_scan = None
            for scan in malicious_host.scans:
                if scan.start_offset <= timestamp <= scan.end_offset:
                    current_scan = scan
                    break

            if current_scan is None:
                current_scan = Scan(timestamp, timestamp, None, self.buffer)
                malicious_host.scans.append(current_scan)
            else:
                if timestamp < current_scan.start:
                    current_scan.setStartTime(timestamp)
                if timestamp > current_scan.end:
                    current_scan.setEndTime(timestamp)
                current_scan.hits += 1

            if hit.destination.ip in current_scan.targets:
                target = current_scan.targets[hit.destination.ip]
                target.hits += 1

                if timestamp < target.start:
                    target.start = timestamp
                if timestamp > target.end:
                    target.end = timestamp
            else:
                target = ScanTarget(hit.destination.ip, timestamp)
                current_scan.targets[hit.destination.ip] = target
        return malicious_hosts

    def process_ping_search(self, search: Search):
        malicious_hosts: dict[str, ScanHost] = {}
        search = search.execute()
        for item in search.aggregations.source.buckets:
            self.helper.log_info(f"Processing {item.key} pinged {item.doc_count} times")
            if item.key in malicious_hosts:
                malicious_host = malicious_hosts[item.key]
            else:
                malicious_host = ScanHost(item.key)
                malicious_hosts[item.key] = malicious_host
                malicious_host.hits += item.doc_count

            current_incident = {}
            for history_item in item.history.buckets:
                if "end_time" in current_incident:
                    if current_incident["end_time"] == history_item.key:
                        current_incident["end_time"] = history_item.key + self.buffer.seconds
                        current_incident["hit_count"] = current_incident["hit_count"] + \
                                                        history_item.doc_count
                    else:
                        # self.helper.log_info(f"{current_incident}")
                        my_incident = self.incident_manager.find_or_create_incident(
                            current_incident["start_time"],
                            current_incident["end_time"]
                        )

                        nmap_scan = Scan(
                            datetime.fromtimestamp(current_incident["start_time"] / 1000, tz=pytz.UTC),
                            datetime.fromtimestamp(current_incident["end_time"] / 1000, tz=pytz.UTC),
                            my_incident,
                            self.buffer
                        )
                        nmap_scan.hits = current_incident["hit_count"]
                        malicious_host.scans.append(nmap_scan)
                        current_incident = {}
                else:
                    current_incident["start_time"] = history_item.key
                    current_incident["end_time"] = history_item.key + 300000
                    current_incident["hit_count"] = history_item.doc_count

        for malicious_host_key in malicious_hosts:
            malicious_host = malicious_hosts[malicious_host_key]
            for scan in malicious_host.scans:
                search = self.get_follow_up_query(malicious_host_key, scan.start, scan.end)
                search = search.execute()

                try:
                    for item in search.aggregations.destination.buckets:
                        self.helper.log_info(f"Processing {item.key} pinged {item.doc_count} times")

                        if "min_date" in item:
                            target = ScanTarget(item.key, ciso8601.parse_datetime(item.min_date.value_as_string))
                            target.end = ciso8601.parse_datetime(item.max_date.value_as_string)
                        else:
                            target = ScanTarget(item.key,scan.start)
                            target.end = scan.end

                        scan.targets[item.key] = target
                        target.hits = item.doc_count
                except Exception:
                    pass
        return malicious_hosts

    def process_nmap_results(self, malicious_hosts):
        attack_pattern = self.get_attack_pattern_and_kill_chain_phases("NETWORK SERVICE SCANNING")
        kill_chain_phases = []
        if "killChainPhases" in attack_pattern:
            for kcp in attack_pattern["killChainPhases"]:
                kill_chain_phases.append(kcp["standard_id"])
        scripting_attack_pattern = self.get_attack_pattern_and_kill_chain_phases("SCRIPTING")
        scripting_kill_chain_phases = []
        if "killChainPhases" in scripting_attack_pattern:
            for kcp in scripting_attack_pattern["killChainPhases"]:
                scripting_kill_chain_phases.append(kcp["standard_id"])
        for malicious_host_key in malicious_hosts:
            malicious_host = malicious_hosts[malicious_host_key]
            if malicious_host.id is None:
                if re.match(self.ipv4_pattern, malicious_host_key):
                    ipv4_address: IPv4Address = self.env_manager.find_or_create_ipv4(malicious_host_key)
                    self.helper.log_info(f"IPv4Address is {ipv4_address}")
                    malicious_host.id = ipv4_address["standard_id"]
                else:
                    ipv6_address = self.env_manager.find_or_create_ipv6(malicious_host_key)
                    self.helper.log_info(f"IPv6Address is {ipv6_address}")
                    malicious_host.id = ipv6_address["standard_id"]

            self.helper.api.stix_cyber_observable.add_label(
                id=malicious_host.id,
                label_name="malicious-activity"
            )

            self.env_manager.add_item_to_report(malicious_host.id)

            self.helper.log_info(f"{malicious_host.id}")
            for scan in malicious_host.scans:
                my_incident = self.incident_manager.find_or_create_incident(scan.start.timestamp() * 1000,
                                                                            scan.end.timestamp() * 1000)
                if my_incident.stix_id == "":
                    self.incident_manager.write_incident_to_opencti(my_incident)

                self.ssh_scanner.add_known_malicious_incident(malicious_host_key, my_incident)

                description = f"{malicious_host_key} nmap scanned {len(scan.targets)} hosts total of {scan.hits} " + \
                              f"times during this scan."
                relationship = self.relationship_manager.find_or_create_relationship(
                    relationship_type="related-to",
                    fromId=malicious_host.id,
                    toId=my_incident.stix_id,
                    start_time=scan.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    stop_time=scan.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    confidence=self.confidence,
                    createdBy=self.author,
                    description=description
                )
                if relationship is not None:
                    self.env_manager.add_item_to_report(relationship["standard_id"])

                self.link_attack_pattern(my_incident,
                                         attack_pattern["attack_pattern"],
                                         scan,
                                         attack_pattern["kill_chain_phases"] if "kill_chain_phases" in
                                                                                attack_pattern else None)
                self.link_attack_pattern(my_incident,
                                         scripting_attack_pattern["attack_pattern"],
                                         scan,
                                         scripting_attack_pattern["kill_chain_phases"] if "kill_chain_phases" in
                                                                                          scripting_attack_pattern else None)

                tool = self.helper.api.tool.read(
                    filters={"key": "name", "values": ["Nmap"]}
                )
                if tool is None:
                    tool = self.helper.api.tool.create(
                        name="Nmap",
                        description="Nmap is used to scan for listening ports on a host.",
                        createdBy=self.author
                    )
                if tool is not None:
                    self.link_tool(my_incident, tool, scan)

                for target_key in scan.targets:
                    target = scan.targets[target_key]
                    ip_sector = self.env_manager.get_sector_for_ip_addr(target_key)
                    if ip_sector is not None:
                        self.env_manager.add_item_to_report(ip_sector)
                        relationship = self.relationship_manager.find_or_create_relationship(
                            relationship_type="targets",
                            fromId=my_incident.stix_id,
                            toId=ip_sector,
                            start_time=target.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            stop_time=target.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            confidence=self.confidence,
                            createdBy=self.author
                        )
                        if relationship is not None:
                            self.env_manager.add_item_to_report(relationship["standard_id"])

                    for threat_actor in self.env_manager.threat_actors:
                        relationship = self.relationship_manager.find_or_create_relationship(
                            relationship_type="targets",
                            fromId=threat_actor,
                            toId=ip_sector,
                            start_time=target.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            stop_time=target.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            confidence=self.confidence,
                            createdBy=self.author
                        )
                        if relationship is not None:
                            self.env_manager.add_item_to_report(relationship["standard_id"])

                    for intrusion_set in self.env_manager.intrusion_sets:
                        relationship = self.relationship_manager.find_or_create_relationship(
                            relationship_type="targets",
                            fromId=intrusion_set,
                            toId=ip_sector,
                            start_time=target.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            stop_time=target.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            confidence=self.confidence,
                            createdBy=self.author
                        )
                        if relationship is not None:
                            self.env_manager.add_item_to_report(relationship["standard_id"])

                    target_id = None
                    if re.match(self.ipv4_pattern, target_key):
                        ipv4_address: IPv4Address = self.env_manager.find_or_create_ipv4(target_key)
                        self.helper.log_info(f"IPv4Address is {ipv4_address}")
                        target_id = ipv4_address["standard_id"]
                    else:
                        ipv6_address = self.env_manager.find_or_create_ipv6(target_key)
                        self.helper.log_info(f"IPv6Address is {ipv6_address}")
                        target_id = ipv6_address["standard_id"]

                    if target_id is not None:
                        self.env_manager.add_item_to_report(target_id)
                        observed_data = self.helper.api.observed_data.create(
                            createdBy=self.author,
                            first_observed=target.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            last_observed=target.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            objects=[target_id, my_incident.stix_id,
                                     malicious_host.id, attack_pattern["attack_pattern"]["standard_id"],
                                     scripting_attack_pattern["attack_pattern"]["standard_id"]],
                            number_observed=target.hits,
                            confidence=self.confidence
                        )
                        if observed_data is not None:
                            self.env_manager.add_item_to_report(observed_data["standard_id"])

                        description = f"{malicious_host_key} nmap scanned {target_key} a total of {target.hits} " + \
                                      f"times during this scan."

                        relationship = self.relationship_manager.find_or_create_relationship(
                            relationship_type="related-to",
                            fromId=target_id,
                            toId=my_incident.stix_id,
                            start_time=target.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            stop_time=target.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            confidence=self.confidence,
                            createdBy=self.author,
                            description=description
                        )
                        if relationship is not None:
                            self.env_manager.add_item_to_report(relationship["standard_id"])
                        self.helper.api.stix_cyber_observable.add_label(
                            id=target_id,
                            label_name="targeted"
                        )

    def process_ping_results(self, malicious_hosts):
        attack_pattern = self.get_attack_pattern_and_kill_chain_phases("T1018")
        kill_chain_phases = []
        if "killChainPhases" in attack_pattern:
            for kcp in attack_pattern["killChainPhases"]:
                kill_chain_phases.append(kcp["standard_id"])
        scripting_attack_pattern = self.get_attack_pattern_and_kill_chain_phases("SCRIPTING")
        scripting_kill_chain_phases = []
        if "killChainPhases" in scripting_attack_pattern:
            for kcp in scripting_attack_pattern["killChainPhases"]:
                scripting_kill_chain_phases.append(kcp["standard_id"])
        for malicious_host_key in malicious_hosts:
            malicious_host = malicious_hosts[malicious_host_key]
            if malicious_host.id is None:
                if re.match(self.ipv4_pattern, malicious_host_key):
                    ipv4_address: IPv4Address = self.env_manager.find_or_create_ipv4(malicious_host_key)
                    self.helper.log_info(f"IPv4Address is {ipv4_address}")
                    malicious_host.id = ipv4_address["standard_id"]
                else:
                    ipv6_address = self.env_manager.find_or_create_ipv6(malicious_host_key)
                    self.helper.log_info(f"IPv6Address is {ipv6_address}")
                    malicious_host.id = ipv6_address["standard_id"]

            self.helper.api.stix_cyber_observable.add_label(
                id=malicious_host.id,
                label_name="malicious-activity"
            )

            self.env_manager.add_item_to_report(malicious_host.id)

            self.helper.log_info(f"{malicious_host.id}")
            for scan in malicious_host.scans:
                my_incident = self.incident_manager.find_or_create_incident(scan.start.timestamp() * 1000,
                                                                            scan.end.timestamp() * 1000)
                if my_incident.stix_id == "":
                    self.incident_manager.write_incident_to_opencti(my_incident)

                self.ssh_scanner.add_known_malicious_incident(malicious_host_key, my_incident)

                description = f"{malicious_host_key} pinged {len(scan.targets)} hosts total of {scan.hits} " + \
                              f"times during this scan."
                relationship = self.relationship_manager.find_or_create_relationship(
                    relationship_type="related-to",
                    fromId=malicious_host.id,
                    toId=my_incident.stix_id,
                    start_time=scan.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    stop_time=scan.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    confidence=self.confidence,
                    createdBy=self.author,
                    description=description
                )
                if relationship is not None:
                    self.env_manager.add_item_to_report(relationship["standard_id"])

                self.link_attack_pattern(my_incident,
                                         attack_pattern["attack_pattern"],
                                         scan,
                                         attack_pattern["kill_chain_phases"] if "kill_chain_phases" in
                                                                                attack_pattern else None)
                self.link_attack_pattern(my_incident,
                                         scripting_attack_pattern["attack_pattern"],
                                         scan,
                                         scripting_attack_pattern["kill_chain_phases"] if "kill_chain_phases" in
                                                                                          scripting_attack_pattern else None)

                tool = self.helper.api.tool.read(
                    filters={"key": "name", "values": ["Ping"]}
                )
                if tool is None:
                    tool = self.helper.api.tool.create(
                        name="Ping",
                        description="Ping is locate other computers on a network.",
                        createdBy=self.author
                    )
                if tool is not None:
                    self.link_tool(my_incident, tool, scan)
                for target_key in scan.targets:
                    target = scan.targets[target_key]
                    ip_sector = self.env_manager.get_sector_for_ip_addr(target_key)
                    if ip_sector is not None:
                        self.env_manager.add_item_to_report(ip_sector)
                        relationship = self.relationship_manager.find_or_create_relationship(
                            relationship_type="targets",
                            fromId=my_incident.stix_id,
                            toId=ip_sector,
                            start_time=target.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            stop_time=target.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            confidence=self.confidence,
                            createdBy=self.author
                        )
                        if relationship is not None:
                            self.env_manager.add_item_to_report(relationship["standard_id"])

                    for threat_actor in self.env_manager.threat_actors:
                        relationship = self.relationship_manager.find_or_create_relationship(
                            relationship_type="targets",
                            fromId=threat_actor,
                            toId=ip_sector,
                            start_time=target.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            stop_time=target.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            confidence=self.confidence,
                            createdBy=self.author
                        )
                        if relationship is not None:
                            self.env_manager.add_item_to_report(relationship["standard_id"])

                    for intrusion_set in self.env_manager.intrusion_sets:
                        relationship = self.relationship_manager.find_or_create_relationship(
                            relationship_type="targets",
                            fromId=intrusion_set,
                            toId=ip_sector,
                            start_time=target.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            stop_time=target.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            confidence=self.confidence,
                            createdBy=self.author
                        )
                        if relationship is not None:
                            self.env_manager.add_item_to_report(relationship["standard_id"])

                    target_id = None
                    if re.match(self.ipv4_pattern, target_key):
                        ipv4_address: IPv4Address = self.env_manager.find_or_create_ipv4(target_key)
                        self.helper.log_info(f"IPv4Address is {ipv4_address}")
                        target_id = ipv4_address["standard_id"]
                    else:
                        ipv6_address = self.env_manager.find_or_create_ipv6(target_key)
                        self.helper.log_info(f"IPv6Address is {ipv6_address}")
                        target_id = ipv6_address["standard_id"]

                    if target_id is not None:
                        self.env_manager.add_item_to_report(target_id)
                        observed_data = self.helper.api.observed_data.create(
                            createdBy=self.author,
                            first_observed=target.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            last_observed=target.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            objects=[target_id, my_incident.stix_id,
                                     malicious_host.id, attack_pattern["attack_pattern"]["standard_id"],
                                     scripting_attack_pattern["attack_pattern"]["standard_id"]],
                            number_observed=target.hits,
                            confidence=self.confidence
                        )
                        if observed_data is not None:
                            self.env_manager.add_item_to_report(observed_data["standard_id"])
                        description = f"{malicious_host_key} pinged {target_key} a total of {target.hits} " + \
                                      f"times during this scan."

                        relationship = self.relationship_manager.find_or_create_relationship(
                            relationship_type="related-to",
                            fromId=target_id,
                            toId=my_incident.stix_id,
                            start_time=target.start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            stop_time=target.end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                            confidence=self.confidence,
                            createdBy=self.author,
                            description=description
                        )
                        if relationship is not None:
                            self.env_manager.add_item_to_report(relationship["standard_id"])
                        self.helper.api.stix_cyber_observable.add_label(
                            id=target_id,
                            label_name="targeted"
                        )

    def run(self) -> None:
        self.helper.log_info("Nmap scanner thread starting")

        """Main loop"""
        while not self.shutdown_event.is_set():
            try:
                run_stuff = self.get_should_run(self.state_tracking_token)
                if "should_run" in run_stuff and run_stuff["should_run"]:
                    now = datetime.utcfromtimestamp(run_stuff["timestamp"])
                    last_timestamp = datetime.utcfromtimestamp(run_stuff["last_run"]) if run_stuff["last_run"] is not \
                                                                                         None else None

                    search: Search = self.get_nmap_ssh_traffic_query(start=last_timestamp, end=now)
                    malicious_hosts = self.process_nmap_search(search)
                    self.helper.log_info(f"Processing {len(malicious_hosts)} malicious hosts")
                    self.process_nmap_results(malicious_hosts)

                    search: Search = self.get_public_agg_query(start=last_timestamp, end=now)
                    malicious_hosts = self.process_ping_search(search)
                    self.helper.log_info(f"Processing {len(malicious_hosts)} malicious hosts")
                    self.process_ping_results(malicious_hosts)

                    search: Search = self.get_private_agg_query(start=last_timestamp, end=now)
                    malicious_hosts = self.process_ping_search(search)
                    self.helper.log_info(f"Processing {len(malicious_hosts)} malicious hosts")
                    self.process_ping_results(malicious_hosts)

                    self.mark_last_run(self.state_tracking_token, run_stuff["timestamp"])
                self.shutdown_event.wait(self.interval)
            except Exception as e:
                self.helper.log_error(f"Exception in ping scanner {e}")
                traceback.print_exc()

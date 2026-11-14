from app.opnsense.normalise.aliases import AliasesResult, AliasInfo, normalise_aliases
from app.opnsense.normalise.dns import DnsResult, TopDomain, normalise_dns
from app.opnsense.normalise.dnsmasq import (
    DomainInfo,
    DomainsResult,
    HostInfo,
    HostsResult,
    normalise_domains,
    normalise_hosts,
)
from app.opnsense.normalise.interfaces import InterfaceInfo, normalise_interfaces
from app.opnsense.normalise.leases import LeaseInfo, LeasesResult, normalise_leases
from app.opnsense.normalise.logs import (
    LogEntry,
    LogResult,
    LogSummary,
    TopItem,
    log_cursor,
    normalise_log,
    summarise_log,
)
from app.opnsense.normalise.nat import NatResult, NatRule, normalise_nat
from app.opnsense.normalise.rules import RuleInfo, RulesResult, normalise_rules
from app.opnsense.normalise.services import ServiceInfo, ServicesResult, normalise_services
from app.opnsense.normalise.system import (
    SystemStatus,
    normalise_cpu_events,
    normalise_system_status,
)
from app.opnsense.normalise.traffic import TrafficInterface, TrafficResult, normalise_traffic
from app.opnsense.normalise.wireguard import WireguardRecord, WireguardResult, normalise_wireguard

__all__ = [
    "AliasInfo",
    "AliasesResult",
    "DnsResult",
    "DomainInfo",
    "DomainsResult",
    "HostInfo",
    "HostsResult",
    "InterfaceInfo",
    "LeaseInfo",
    "LeasesResult",
    "LogEntry",
    "LogResult",
    "LogSummary",
    "NatResult",
    "NatRule",
    "RuleInfo",
    "RulesResult",
    "ServiceInfo",
    "ServicesResult",
    "SystemStatus",
    "TopDomain",
    "TopItem",
    "TrafficInterface",
    "TrafficResult",
    "WireguardRecord",
    "WireguardResult",
    "log_cursor",
    "normalise_aliases",
    "normalise_cpu_events",
    "normalise_dns",
    "normalise_domains",
    "normalise_hosts",
    "normalise_interfaces",
    "normalise_leases",
    "normalise_log",
    "normalise_nat",
    "normalise_rules",
    "normalise_services",
    "normalise_system_status",
    "normalise_traffic",
    "normalise_wireguard",
    "summarise_log",
]

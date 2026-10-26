from __future__ import annotations

import importlib
from typing import Dict, List, Type

from vuln_agent.agents.base import Agent

# Add feature: implement Agent + register here + enable in config/default.yaml
AGENT_ENTRYPOINTS: Dict[str, str] = {
    "recon": "vuln_agent.agents.recon:ReconAgent",
    "users": "vuln_agent.agents.users:UsersAgent",
    "auth": "vuln_agent.agents.auth:AuthAgent",
    "leaks": "vuln_agent.agents.leaks:LeaksAgent",
    "cors_api": "vuln_agent.agents.cors_api:CorsApiAgent",
    "upload": "vuln_agent.agents.upload:UploadAgent",
    "js_audit": "vuln_agent.agents.js_audit:JsAuditAgent",
    "uat_app": "vuln_agent.agents.uat_app:UatAppAgent",
    "ports_mail": "vuln_agent.agents.ports_mail:PortsMailAgent",
    "tls_headers": "vuln_agent.agents.tls_headers:TlsHeadersAgent",
    "cloud_storage": "vuln_agent.agents.cloud_storage:CloudStorageAgent",
    "admin_panels": "vuln_agent.agents.admin_panels:AdminPanelsAgent",
    "email_spoof": "vuln_agent.agents.email_spoof:EmailSpoofAgent",
    "js_secrets": "vuln_agent.agents.js_secrets:JsSecretsAgent",
    "sitemap_crawl": "vuln_agent.agents.sitemap_crawl:SitemapCrawlAgent",
    "graphql": "vuln_agent.agents.graphql_agent:GraphqlAgent",
    "websocket": "vuln_agent.agents.websocket_agent:WebsocketAgent",
    "cookie_flags": "vuln_agent.agents.cookie_flags:CookieFlagsAgent",
    "oauth_misconfig": "vuln_agent.agents.oauth_misconfig:OauthMisconfigAgent",
    "jwt_public": "vuln_agent.agents.jwt_public:JwtPublicAgent",
    "redirect_open": "vuln_agent.agents.redirect_open:RedirectOpenAgent",
    "http_methods": "vuln_agent.agents.http_methods:HttpMethodsAgent",
    "cors_creds": "vuln_agent.agents.cors_creds:CorsCredsAgent",
    "subdomain_hint": "vuln_agent.agents.subdomain_hint:SubdomainHintAgent",
    "dns_hygiene": "vuln_agent.agents.dns_hygiene:DnsHygieneAgent",
    "caa_dnssec": "vuln_agent.agents.caa_dnssec:CaaDnssecAgent",
    "cdn_origin": "vuln_agent.agents.cdn_origin:CdnOriginAgent",
    "wordpress_deep": "vuln_agent.agents.wordpress_deep:WordpressDeepAgent",
    "next_react": "vuln_agent.agents.next_react:NextReactAgent",
    "spring_java": "vuln_agent.agents.spring_java:SpringJavaAgent",
    "firebase": "vuln_agent.agents.firebase_agent:FirebaseAgent",
    "cache_poison_hint": "vuln_agent.agents.cache_poison_hint:CachePoisonHintAgent",
    "rate_limit_probe": "vuln_agent.agents.rate_limit_probe:RateLimitProbeAgent",
    "dependency_meta": "vuln_agent.agents.dependency_meta:DependencyMetaAgent",
    "input_hygiene": "vuln_agent.agents.input_hygiene:InputHygieneAgent",
    "csrf_forms": "vuln_agent.agents.csrf_forms:CsrfFormsAgent",
    "access_hint": "vuln_agent.agents.access_hint:AccessHintAgent",
    "ssrf_hint": "vuln_agent.agents.ssrf_hint:SsrfHintAgent",
    "xss_reflect_safe": "vuln_agent.agents.xss_reflect_safe:XssReflectSafeAgent",
    "auth_enum": "vuln_agent.agents.auth_enum:AuthEnumAgent",
    "cve_stack": "vuln_agent.agents.cve_stack:CveStackAgent",
    "tls_depth": "vuln_agent.agents.tls_depth:TlsDepthAgent",
    "adapt": "vuln_agent.agents.adapt:AdaptAgent",
    "compliance_map": "vuln_agent.agents.compliance_map:ComplianceMapAgent",
    "executive_brief": "vuln_agent.agents.executive_brief:ExecutiveBriefAgent",
    "reporter": "vuln_agent.agents.reporter:ReporterAgent",
}


def _import_symbol(path: str) -> Type[Agent]:
    module_path, _, attr = path.partition(":")
    if not module_path or not attr:
        raise ValueError(f"invalid entrypoint: {path}")
    module = importlib.import_module(module_path)
    return getattr(module, attr)


def load_agents(enabled: List[str]) -> List[Agent]:
    agents: List[Agent] = []
    for name in enabled:
        entry = AGENT_ENTRYPOINTS.get(name)
        if not entry:
            raise KeyError(f"unknown agent '{name}' — add it to AGENT_ENTRYPOINTS")
        cls = _import_symbol(entry)
        agents.append(cls())
    return agents

"""
Research API endpoints.

Provides:
- WHOIS lookups for domains and IPs
- DNS record lookups
- ASN information lookups
- Shodan integration (optional)
- Maltego transforms (optional)
- Research configuration status
"""

from datetime import datetime
from typing import Optional

import structlog
from api.v1.auth import auth_required
from models.db import get_db
from pydantic import ValidationError
from quart import Blueprint, current_app, g, jsonify, request
from services.research import (
    ASNClient,
    DNSClient,
    IndicatorClassifier,
    MaltegoClient,
    ShodanClient,
    WhoisClient,
)
from validators.pydantic_models import (
    AsnLookupRequest,
    AsnResultModel,
    DnsLookupRequest,
    DnsResultModel,
    MaltegoResultModel,
    ResearchConfigResponse,
    ResearchIndicatorType,
    ResearchLookupRequest,
    ResearchLookupResponse,
    ShodanResultModel,
    WhoisLookupRequest,
    WhoisResultModel,
)

logger = structlog.get_logger(__name__)

research_bp = Blueprint("research", __name__, url_prefix="/api/v1/research")


def _get_research_clients(config):
    """Initialize research service clients."""
    research_config = config.research
    return {
        "whois": WhoisClient(timeout=research_config.whois_timeout),
        "dns": DNSClient(timeout=research_config.dns_timeout),
        "asn": ASNClient(timeout=research_config.asn_timeout),
        "shodan": ShodanClient(
            api_key=research_config.shodan_api_key,
            enabled=research_config.shodan_enabled,
        ),
        "maltego": MaltegoClient(
            trx_server=research_config.maltego_trx_server,
            enabled=research_config.maltego_enabled,
        ),
        "classifier": IndicatorClassifier(),
    }


@research_bp.route("/lookup", methods=["POST"])
@auth_required
async def lookup():
    """
    Main research lookup endpoint.

    Performs comprehensive research on an indicator across multiple sources.
    Supports WHOIS, DNS, ASN, Shodan, and Maltego lookups.
    """
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        lookup_request = ResearchLookupRequest(**data)
    except ValidationError as e:
        logger.warning("research_lookup_validation_error", errors=e.errors())
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    logger.info(
        "research_lookup_start",
        query=lookup_request.query,
        indicator_type=lookup_request.indicator_type,
    )

    clients = _get_research_clients(config)

    # Classify indicator if not specified
    indicator_type = lookup_request.indicator_type
    if not indicator_type:
        indicator_type = clients["classifier"].classify(lookup_request.query)

    result = {
        "query": lookup_request.query,
        "indicator_type": indicator_type.value if indicator_type else None,
        "timestamp": datetime.utcnow(),
    }

    # WHOIS lookup
    if lookup_request.include_whois and indicator_type.value in ["domain", "ip"]:
        try:
            whois_result = await clients["whois"].lookup(
                lookup_request.query,
                timeout=lookup_request.timeout,
            )
            if whois_result.success:
                result["whois"] = {
                    "success": True,
                    "data": whois_result.data,
                }
            else:
                result["whois"] = {
                    "success": False,
                    "error": whois_result.error,
                }
            logger.debug("research_whois_complete", query=lookup_request.query)
        except Exception as e:
            logger.error(
                "research_whois_error",
                query=lookup_request.query,
                error=str(e),
            )
            result["whois"] = {"success": False, "error": str(e)}

    # DNS lookup
    if lookup_request.include_dns and indicator_type.value == "domain":
        try:
            dns_result = await clients["dns"].lookup(
                lookup_request.query,
                timeout=lookup_request.timeout,
            )
            result["dns"] = dns_result.to_dict()
            logger.debug("research_dns_complete", query=lookup_request.query)
        except Exception as e:
            logger.error(
                "research_dns_error",
                query=lookup_request.query,
                error=str(e),
            )
            result["dns"] = {"error": str(e)}

    # ASN lookup
    if lookup_request.include_asn and indicator_type.value in ["ip", "asn"]:
        try:
            asn_result = await clients["asn"].lookup_ip(lookup_request.query)
            result["asn"] = asn_result if asn_result else {"error": "No results"}
            logger.debug("research_asn_complete", query=lookup_request.query)
        except Exception as e:
            logger.error(
                "research_asn_error",
                query=lookup_request.query,
                error=str(e),
            )
            result["asn"] = {"error": str(e)}

    # Shodan lookup
    if lookup_request.include_shodan:
        if not clients["shodan"].enabled:
            logger.debug("research_shodan_disabled")
            return jsonify({"error": "Shodan not enabled"}), 503

        try:
            shodan_result = await clients["shodan"].lookup_ip(lookup_request.query)
            result["shodan"] = (
                shodan_result if shodan_result else {"error": "No results"}
            )
            logger.debug("research_shodan_complete", query=lookup_request.query)
        except Exception as e:
            logger.error(
                "research_shodan_error",
                query=lookup_request.query,
                error=str(e),
            )
            result["shodan"] = {"error": str(e)}

    # Maltego lookup
    if lookup_request.include_maltego:
        if not clients["maltego"].enabled:
            logger.debug("research_maltego_disabled")
            return jsonify({"error": "Maltego not enabled"}), 503

        try:
            if indicator_type.value == "domain":
                maltego_result = await clients["maltego"].domain_transforms(
                    lookup_request.query
                )
            else:
                maltego_result = await clients["maltego"].ip_transforms(
                    lookup_request.query
                )
            result["maltego"] = (
                maltego_result if maltego_result else {"error": "No results"}
            )
            logger.debug("research_maltego_complete", query=lookup_request.query)
        except Exception as e:
            logger.error(
                "research_maltego_error",
                query=lookup_request.query,
                error=str(e),
            )
            result["maltego"] = {"error": str(e)}

    logger.info("research_lookup_complete", query=lookup_request.query)
    return jsonify(result), 200


@research_bp.route("/whois", methods=["POST"])
@auth_required
async def whois_lookup():
    """
    WHOIS-only lookup endpoint.

    Queries WHOIS information for domains and IP addresses.
    """
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        whois_request = WhoisLookupRequest(**data)
    except ValidationError as e:
        logger.warning("research_whois_validation_error", errors=e.errors())
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    logger.info("research_whois_lookup_start", query=whois_request.query)

    clients = _get_research_clients(config)

    try:
        result = await clients["whois"].lookup(whois_request.query)

        response = {
            "success": result.success,
            "data": result.data,
            "error": result.error,
        }

        logger.info("research_whois_lookup_complete", query=whois_request.query)
        return jsonify(response), 200
    except Exception as e:
        logger.error(
            "research_whois_lookup_error",
            query=whois_request.query,
            error=str(e),
        )
        return (
            jsonify({"error": "WHOIS lookup failed", "details": str(e)}),
            500,
        )


@research_bp.route("/dns", methods=["POST"])
@auth_required
async def dns_lookup():
    """
    DNS-only lookup endpoint.

    Queries DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) for a domain.
    """
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        dns_request = DnsLookupRequest(**data)
    except ValidationError as e:
        logger.warning("research_dns_validation_error", errors=e.errors())
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    logger.info("research_dns_lookup_start", query=dns_request.query)

    clients = _get_research_clients(config)

    try:
        result = await clients["dns"].lookup(dns_request.query)

        response = result.to_dict()

        logger.info("research_dns_lookup_complete", query=dns_request.query)
        return jsonify(response), 200
    except Exception as e:
        logger.error(
            "research_dns_lookup_error",
            query=dns_request.query,
            error=str(e),
        )
        return (
            jsonify({"error": "DNS lookup failed", "details": str(e)}),
            500,
        )


@research_bp.route("/asn", methods=["POST"])
@auth_required
async def asn_lookup():
    """
    ASN-only lookup endpoint.

    Queries ASN information for IP addresses or ASN numbers using Team Cymru DNS.
    """
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        asn_request = AsnLookupRequest(**data)
    except ValidationError as e:
        logger.warning("research_asn_validation_error", errors=e.errors())
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    logger.info("research_asn_lookup_start", query=asn_request.query)

    clients = _get_research_clients(config)

    try:
        if asn_request.indicator_type.value == "asn":
            result = await clients["asn"].lookup_asn(asn_request.query)
        else:
            result = await clients["asn"].lookup_ip(asn_request.query)

        response = result if result else {"error": "No ASN data found"}

        logger.info("research_asn_lookup_complete", query=asn_request.query)
        return jsonify(response), 200
    except Exception as e:
        logger.error(
            "research_asn_lookup_error",
            query=asn_request.query,
            error=str(e),
        )
        return (
            jsonify({"error": "ASN lookup failed", "details": str(e)}),
            500,
        )


@research_bp.route("/shodan", methods=["POST"])
@auth_required
async def shodan_lookup():
    """
    Shodan-only lookup endpoint.

    Queries Shodan for IP address intelligence.
    Returns 503 if Shodan is not enabled.
    """
    config = current_app.config["MANAGER_CONFIG"]

    clients = _get_research_clients(config)

    if not clients["shodan"].enabled:
        logger.warning("research_shodan_disabled")
        return (
            jsonify(
                {
                    "error": "Shodan integration not enabled",
                    "details": "Please configure Shodan API key and enable integration",
                }
            ),
            503,
        )

    try:
        data = await request.get_json()
        if not data or "query" not in data:
            return (
                jsonify({"error": "Query field required"}),
                400,
            )
        query = data["query"]
    except Exception as e:
        logger.warning("research_shodan_parse_error", error=str(e))
        return jsonify({"error": "Invalid request format"}), 400

    logger.info("research_shodan_lookup_start", query=query)

    try:
        result = await clients["shodan"].lookup_ip(query)

        response = result if result else {"error": "No Shodan data found"}

        logger.info("research_shodan_lookup_complete", query=query)
        return jsonify(response), 200
    except Exception as e:
        logger.error(
            "research_shodan_lookup_error",
            query=query,
            error=str(e),
        )
        return (
            jsonify({"error": "Shodan lookup failed", "details": str(e)}),
            500,
        )


@research_bp.route("/maltego", methods=["POST"])
@auth_required
async def maltego_lookup():
    """
    Maltego transforms endpoint.

    Queries Maltego for open source intelligence transforms.
    Returns 503 if Maltego is not enabled.
    """
    config = current_app.config["MANAGER_CONFIG"]

    clients = _get_research_clients(config)

    if not clients["maltego"].enabled:
        logger.warning("research_maltego_disabled")
        return (
            jsonify(
                {
                    "error": "Maltego integration not enabled",
                    "details": "Please configure Maltego and enable integration",
                }
            ),
            503,
        )

    try:
        data = await request.get_json()
        if not data or "query" not in data:
            return (
                jsonify({"error": "Query field required"}),
                400,
            )
        query = data["query"]
        indicator_type = data.get("indicator_type", "domain")
    except Exception as e:
        logger.warning("research_maltego_parse_error", error=str(e))
        return jsonify({"error": "Invalid request format"}), 400

    logger.info(
        "research_maltego_lookup_start",
        query=query,
        indicator_type=indicator_type,
    )

    try:
        if indicator_type == "domain":
            result = await clients["maltego"].domain_transforms(query)
        else:
            result = await clients["maltego"].ip_transforms(query)

        response = result if result else {"error": "No Maltego data found"}

        logger.info("research_maltego_lookup_complete", query=query)
        return jsonify(response), 200
    except Exception as e:
        logger.error(
            "research_maltego_lookup_error",
            query=query,
            error=str(e),
        )
        return (
            jsonify({"error": "Maltego lookup failed", "details": str(e)}),
            500,
        )


@research_bp.route("/config", methods=["GET"])
@auth_required
async def get_config():
    """
    Get research configuration status.

    Returns information about enabled research sources and configured timeouts.
    """
    config = current_app.config["MANAGER_CONFIG"]
    research_config = config.research

    response = {
        "research_enabled": research_config.enabled,
        "whois_enabled": True,  # WHOIS is always available
        "dns_enabled": True,  # DNS is always available
        "asn_enabled": True,  # ASN lookups are always available
        "shodan_enabled": research_config.shodan_enabled,
        "maltego_enabled": research_config.maltego_enabled,
        "default_timeout": research_config.default_timeout,
        "whois_timeout": research_config.whois_timeout,
        "dns_timeout": research_config.dns_timeout,
        "asn_timeout": research_config.asn_timeout,
        "shodan_timeout": research_config.shodan_timeout,
        "maltego_timeout": research_config.maltego_timeout,
    }

    logger.info("research_config_retrieved")
    return jsonify(response), 200

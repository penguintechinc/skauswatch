"""AI-powered alert review service."""
from datetime import datetime
from typing import Optional, Dict, Any, List

import structlog

from services.ai.provider import AIProvider, AIProviderFactory

logger = structlog.get_logger()


class AlertReviewer:
    """
    AI-powered security alert reviewer.

    Uses AI to:
    - Analyze alert context and severity
    - Identify false positives
    - Suggest remediation actions
    - Correlate related alerts
    - Generate incident summaries
    """

    SYSTEM_PROMPT = """You are a security analyst AI assistant for SkausWatch SIEM.
Your role is to analyze security alerts and provide actionable insights.

When reviewing alerts:
1. Assess the severity and potential impact
2. Identify if it's likely a true positive or false positive
3. Suggest investigation steps
4. Recommend remediation actions
5. Note any related indicators of compromise

Be concise and actionable. Use bullet points for clarity.
Always provide a confidence score (0-100) for your assessment."""

    def __init__(
        self,
        provider_type: str = "ollama",
        provider_config: Dict[str, Any] = None
    ):
        """
        Initialize alert reviewer.

        Args:
            provider_type: AI provider type ('ollama', 'anthropic', 'openai')
            provider_config: Provider-specific configuration
        """
        self.provider_type = provider_type
        self.provider_config = provider_config or {}
        self._provider: Optional[AIProvider] = None

    async def initialize(self) -> None:
        """Initialize the AI provider."""
        self._provider = AIProviderFactory.create(
            self.provider_type,
            self.provider_config
        )

        if self._provider:
            is_healthy = await self._provider.health_check()
            if is_healthy:
                logger.info(
                    "Alert reviewer initialized",
                    provider=self.provider_type,
                    model=self._provider.model
                )
            else:
                logger.warning(
                    "AI provider health check failed",
                    provider=self.provider_type
                )
        else:
            logger.error("Failed to create AI provider")

    @property
    def is_available(self) -> bool:
        """Check if reviewer is available."""
        return self._provider is not None

    async def review_alert(
        self, alert: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Review a single security alert.

        Args:
            alert: Alert data with title, description, severity, indicators, etc.

        Returns:
            Review result with analysis and recommendations
        """
        if not self._provider:
            return {
                "error": "AI provider not available",
                "alert_id": alert.get("id"),
            }

        prompt = self._build_alert_prompt(alert)

        try:
            response = await self._provider.analyze(
                prompt=prompt,
                system=self.SYSTEM_PROMPT,
                temperature=0.3,  # Lower temperature for more consistent analysis
            )

            # Parse the response
            result = self._parse_review_response(response)
            result["alert_id"] = alert.get("id")
            result["reviewed_at"] = datetime.utcnow().isoformat()
            result["provider"] = self.provider_type
            result["model"] = self._provider.model

            logger.info(
                "Alert reviewed",
                alert_id=alert.get("id"),
                verdict=result.get("verdict")
            )

            return result

        except Exception as e:
            logger.error(
                "Alert review failed",
                alert_id=alert.get("id"),
                error=str(e)
            )
            return {
                "error": str(e),
                "alert_id": alert.get("id"),
            }

    async def review_alerts_batch(
        self, alerts: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Review multiple alerts.

        Args:
            alerts: List of alert data

        Returns:
            List of review results
        """
        results = []
        for alert in alerts:
            result = await self.review_alert(alert)
            results.append(result)
        return results

    async def correlate_alerts(
        self, alerts: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze multiple alerts for correlation.

        Args:
            alerts: List of alerts to correlate

        Returns:
            Correlation analysis with related groups and timeline
        """
        if not self._provider:
            return {"error": "AI provider not available"}

        prompt = self._build_correlation_prompt(alerts)

        try:
            response = await self._provider.analyze(
                prompt=prompt,
                system=self.SYSTEM_PROMPT,
                temperature=0.3,
            )

            return {
                "analysis": response,
                "alert_count": len(alerts),
                "analyzed_at": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.error("Alert correlation failed", error=str(e))
            return {"error": str(e)}

    async def generate_incident_summary(
        self, alerts: List[Dict[str, Any]], context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Generate an incident summary from related alerts.

        Args:
            alerts: List of alerts in the incident
            context: Additional context (affected systems, timeline, etc.)

        Returns:
            Incident summary with timeline, impact, and recommendations
        """
        if not self._provider:
            return {"error": "AI provider not available"}

        prompt = self._build_incident_prompt(alerts, context)

        try:
            response = await self._provider.analyze(
                prompt=prompt,
                system=self.SYSTEM_PROMPT,
                temperature=0.3,
            )

            return {
                "summary": response,
                "alert_count": len(alerts),
                "generated_at": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.error("Incident summary generation failed", error=str(e))
            return {"error": str(e)}

    async def suggest_remediation(
        self, alert: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Suggest remediation steps for an alert.

        Args:
            alert: Alert data

        Returns:
            Remediation suggestions
        """
        if not self._provider:
            return {"error": "AI provider not available"}

        prompt = f"""Based on this security alert, provide specific remediation steps:

Alert: {alert.get('title', 'Unknown')}
Severity: {alert.get('severity', 'Unknown')}
Description: {alert.get('description', 'No description')}
Source: {alert.get('source', 'Unknown')}
Indicators: {alert.get('indicators', [])}

Provide:
1. Immediate actions (within 1 hour)
2. Short-term actions (within 24 hours)
3. Long-term preventive measures
4. Commands or scripts if applicable

Be specific and actionable."""

        try:
            response = await self._provider.analyze(
                prompt=prompt,
                system=self.SYSTEM_PROMPT,
                temperature=0.3,
            )

            return {
                "remediation": response,
                "alert_id": alert.get("id"),
                "generated_at": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.error("Remediation suggestion failed", error=str(e))
            return {"error": str(e)}

    def _build_alert_prompt(self, alert: Dict[str, Any]) -> str:
        """Build prompt for alert review."""
        indicators = alert.get("indicators", [])
        indicator_str = "\n".join(f"  - {i}" for i in indicators) if indicators else "None"

        return f"""Review this security alert:

Title: {alert.get('title', 'Unknown')}
Severity: {alert.get('severity', 'Unknown')}
Source: {alert.get('source', 'Unknown')}
Timestamp: {alert.get('timestamp', 'Unknown')}
Description: {alert.get('description', 'No description')}

Indicators of Compromise:
{indicator_str}

Additional Context:
{alert.get('context', 'None')}

Please provide:
1. Verdict: TRUE_POSITIVE, FALSE_POSITIVE, or NEEDS_INVESTIGATION
2. Confidence score (0-100)
3. Brief analysis (2-3 sentences)
4. Recommended next steps (bullet points)
5. Related attack techniques (MITRE ATT&CK if applicable)"""

    def _build_correlation_prompt(self, alerts: List[Dict[str, Any]]) -> str:
        """Build prompt for alert correlation."""
        alert_summaries = []
        for i, alert in enumerate(alerts, 1):
            alert_summaries.append(
                f"{i}. {alert.get('title')} - {alert.get('severity')} "
                f"({alert.get('timestamp')})"
            )

        return f"""Analyze these {len(alerts)} security alerts for correlation:

{chr(10).join(alert_summaries)}

Please identify:
1. Which alerts are likely related?
2. What attack pattern or campaign might this represent?
3. Recommended priority order for investigation
4. Potential attack timeline
5. Common indicators across alerts"""

    def _build_incident_prompt(
        self, alerts: List[Dict[str, Any]], context: Dict[str, Any] = None
    ) -> str:
        """Build prompt for incident summary."""
        context = context or {}

        alert_list = []
        for alert in alerts:
            alert_list.append(
                f"- {alert.get('title')} ({alert.get('severity')}) - "
                f"{alert.get('timestamp')}"
            )

        return f"""Generate an incident summary from these related alerts:

Alerts:
{chr(10).join(alert_list)}

Affected Systems: {context.get('affected_systems', 'Unknown')}
First Seen: {context.get('first_seen', 'Unknown')}
Last Seen: {context.get('last_seen', 'Unknown')}

Provide:
1. Executive summary (2-3 sentences)
2. Timeline of events
3. Impact assessment
4. Root cause analysis (if determinable)
5. Remediation status and next steps
6. Recommendations for preventing recurrence"""

    def _parse_review_response(self, response: str) -> Dict[str, Any]:
        """Parse AI response into structured result."""
        result = {
            "analysis": response,
            "verdict": "NEEDS_INVESTIGATION",
            "confidence": 50,
            "recommendations": [],
        }

        # Extract verdict
        response_lower = response.lower()
        if "true_positive" in response_lower or "true positive" in response_lower:
            result["verdict"] = "TRUE_POSITIVE"
        elif "false_positive" in response_lower or "false positive" in response_lower:
            result["verdict"] = "FALSE_POSITIVE"

        # Extract confidence score
        import re
        confidence_match = re.search(r'confidence[:\s]+(\d+)', response_lower)
        if confidence_match:
            result["confidence"] = int(confidence_match.group(1))

        return result

    async def close(self) -> None:
        """Close the AI provider."""
        if self._provider:
            await self._provider.close()

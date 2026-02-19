"""
SkausWatch AAA Monitor Service - Prompt Templates

Pre-built templates for different log analysis scenarios with dynamic
prompt generation and custom prompt builder.
"""

import json
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from dataclasses import dataclass
import structlog

from .ai_provider import AIAnalysisType

logger = structlog.get_logger(__name__)


class PromptCategory(str, Enum):
    """Prompt template categories"""

    SECURITY_ANALYSIS = "security_analysis"
    ANOMALY_DETECTION = "anomaly_detection"
    THREAT_CLASSIFICATION = "threat_classification"
    LOG_CORRELATION = "log_correlation"
    PATTERN_ANALYSIS = "pattern_analysis"
    INCIDENT_SUMMARY = "incident_summary"
    COMPLIANCE_CHECK = "compliance_check"
    FORENSIC_ANALYSIS = "forensic_analysis"


class PromptComplexity(str, Enum):
    """Prompt complexity levels"""

    SIMPLE = "simple"  # Basic analysis
    DETAILED = "detailed"  # Comprehensive analysis
    EXPERT = "expert"  # Advanced technical analysis


@dataclass
class PromptTemplate:
    """Prompt template definition"""

    name: str
    category: PromptCategory
    analysis_type: AIAnalysisType
    complexity: PromptComplexity
    template: str
    required_fields: List[str]
    optional_fields: List[str]
    description: str
    example_context: Dict[str, Any]


class PromptTemplateManager:
    """Manages prompt templates for AI analysis"""

    def __init__(self):
        """Initialize prompt template manager"""
        self.templates: Dict[str, PromptTemplate] = {}
        self._load_builtin_templates()

    def _load_builtin_templates(self):
        """Load built-in prompt templates"""

        # Security Event Analysis Templates
        self.templates["security_basic"] = PromptTemplate(
            name="security_basic",
            category=PromptCategory.SECURITY_ANALYSIS,
            analysis_type=AIAnalysisType.SECURITY_EVENT,
            complexity=PromptComplexity.SIMPLE,
            template="""
Analyze the following security log events for potential threats:

{log_data}

Please provide:
1. Threat assessment (High/Medium/Low/None)
2. Brief summary of findings
3. Primary security concerns
4. Immediate actions recommended

Context: {context}
""".strip(),
            required_fields=["log_data"],
            optional_fields=["context", "timeframe"],
            description="Basic security event analysis for quick threat assessment",
            example_context={"timeframe": "last_hour", "source": "firewall"},
        )

        self.templates["security_detailed"] = PromptTemplate(
            name="security_detailed",
            category=PromptCategory.SECURITY_ANALYSIS,
            analysis_type=AIAnalysisType.SECURITY_EVENT,
            complexity=PromptComplexity.DETAILED,
            template="""
Perform a comprehensive security analysis of the following log data:

<log_events>
{log_data}
</log_events>

<analysis_context>
Source: {source}
Timeframe: {timeframe}
Environment: {environment}
Previous incidents: {previous_incidents}
</analysis_context>

Please provide a detailed security assessment including:

1. **Executive Summary**
   - Overall threat level and confidence
   - Key findings in 2-3 sentences

2. **Threat Analysis**
   - Specific threats identified
   - Attack vectors and techniques (MITRE ATT&CK mapping if applicable)
   - Affected systems and services

3. **Technical Details**
   - Suspicious patterns and anomalies
   - IOCs (Indicators of Compromise) identified
   - Timeline of events

4. **Risk Assessment**
   - Potential impact (Confidentiality, Integrity, Availability)
   - Likelihood of active threat
   - Business risk implications

5. **Recommendations**
   - Immediate containment actions
   - Investigation priorities
   - Long-term security improvements

6. **Additional Context**
   - Related threat intelligence
   - Similar attack patterns
   - Recommended monitoring

Format your response with clear sections and specific evidence from the log data.
""".strip(),
            required_fields=["log_data", "source"],
            optional_fields=["timeframe", "environment", "previous_incidents"],
            description="Comprehensive security analysis with MITRE ATT&CK mapping",
            example_context={
                "source": "endpoint_detection",
                "timeframe": "last_24_hours",
                "environment": "production",
                "previous_incidents": "none_recent",
            },
        )

        # Anomaly Detection Templates
        self.templates["anomaly_basic"] = PromptTemplate(
            name="anomaly_basic",
            category=PromptCategory.ANOMALY_DETECTION,
            analysis_type=AIAnalysisType.ANOMALY_DETECTION,
            complexity=PromptComplexity.SIMPLE,
            template="""
Identify anomalies in the following log data:

{log_data}

Look for:
- Unusual patterns or frequencies
- Deviations from normal behavior
- Statistical outliers
- Unexpected system behavior

Baseline context: {baseline_context}

Please provide:
1. Anomalies detected (Yes/No)
2. Type of anomaly
3. Severity assessment
4. Brief explanation
""".strip(),
            required_fields=["log_data"],
            optional_fields=["baseline_context", "normal_patterns"],
            description="Basic anomaly detection for log patterns",
            example_context={"baseline_context": "30_day_average"},
        )

        self.templates["anomaly_statistical"] = PromptTemplate(
            name="anomaly_statistical",
            category=PromptCategory.ANOMALY_DETECTION,
            analysis_type=AIAnalysisType.ANOMALY_DETECTION,
            complexity=PromptComplexity.EXPERT,
            template="""
Perform statistical anomaly detection on the following log data:

<log_data>
{log_data}
</log_data>

<baseline_metrics>
{baseline_metrics}
</baseline_metrics>

<detection_parameters>
- Analysis window: {analysis_window}
- Confidence threshold: {confidence_threshold}
- Normal behavior patterns: {normal_patterns}
</detection_parameters>

Please conduct a thorough statistical analysis:

1. **Frequency Analysis**
   - Event count distributions
   - Temporal patterns and trends
   - Rate-based anomalies

2. **Pattern Analysis**
   - Sequence anomalies
   - Correlation deviations
   - Behavioral changes

3. **Statistical Measures**
   - Standard deviation analysis
   - Percentile-based outlier detection
   - Time-series anomalies

4. **Anomaly Classification**
   - Point anomalies (individual events)
   - Contextual anomalies (time/location specific)
   - Collective anomalies (pattern changes)

5. **Significance Assessment**
   - Statistical significance (p-values)
   - Confidence intervals
   - False positive likelihood

6. **Root Cause Hypothesis**
   - Potential causes for anomalies
   - System or environmental factors
   - Actionable insights

Provide quantitative measures where possible and explain your methodology.
""".strip(),
            required_fields=["log_data", "baseline_metrics"],
            optional_fields=[
                "analysis_window",
                "confidence_threshold",
                "normal_patterns",
            ],
            description="Advanced statistical anomaly detection with quantitative analysis",
            example_context={
                "analysis_window": "7_days",
                "confidence_threshold": "95%",
                "normal_patterns": "weekday_business_hours",
            },
        )

        # Threat Classification Templates
        self.templates["threat_classification"] = PromptTemplate(
            name="threat_classification",
            category=PromptCategory.THREAT_CLASSIFICATION,
            analysis_type=AIAnalysisType.THREAT_CLASSIFICATION,
            complexity=PromptComplexity.DETAILED,
            template="""
Classify and categorize the security threats in the following log data:

<security_events>
{log_data}
</security_events>

<threat_context>
Known threat actors: {known_actors}
Recent threat intelligence: {threat_intel}
Industry sector: {industry}
Asset criticality: {asset_criticality}
</threat_context>

Provide comprehensive threat classification:

1. **Threat Identification**
   - Primary threat types identified
   - MITRE ATT&CK tactics and techniques
   - Kill chain stage mapping

2. **Threat Actor Assessment**
   - Sophistication level (Low/Medium/High/Advanced)
   - Likely threat actor profile
   - Motivation assessment (Financial, Espionage, Disruption, etc.)

3. **IOC Analysis**
   - Indicators of Compromise identified
   - IOC confidence ratings
   - Related threat intelligence matches

4. **Risk Classification**
   - Threat severity (Critical/High/Medium/Low)
   - Likelihood of success
   - Potential business impact

5. **Attribution Assessment**
   - Known threat group signatures
   - Geographic or temporal indicators
   - Tool and technique correlations

6. **Countermeasures**
   - Detection signatures recommended
   - Prevention controls
   - Response procedures

Include confidence scores for your assessments.
""".strip(),
            required_fields=["log_data"],
            optional_fields=[
                "known_actors",
                "threat_intel",
                "industry",
                "asset_criticality",
            ],
            description="Comprehensive threat classification with MITRE ATT&CK mapping",
            example_context={
                "known_actors": "APT groups active in region",
                "industry": "financial_services",
                "asset_criticality": "high_value_targets",
            },
        )

        # Log Correlation Templates
        self.templates["correlation_timeline"] = PromptTemplate(
            name="correlation_timeline",
            category=PromptCategory.LOG_CORRELATION,
            analysis_type=AIAnalysisType.LOG_CORRELATION,
            complexity=PromptComplexity.DETAILED,
            template="""
Perform log correlation analysis to reconstruct the sequence of events:

<multi_source_logs>
{log_data}
</multi_source_logs>

<correlation_context>
Time window: {time_window}
Systems involved: {systems}
Initial indicators: {initial_indicators}
</correlation_context>

Please provide detailed correlation analysis:

1. **Event Timeline**
   - Chronological sequence of events
   - Cross-system event correlation
   - Causal relationships identified

2. **Attack Chain Reconstruction**
   - Initial access vector
   - Lateral movement patterns
   - Persistence mechanisms
   - Data exfiltration paths

3. **System Interactions**
   - Inter-system communications
   - Process relationships
   - Network flow analysis

4. **Pattern Recognition**
   - Common attack patterns
   - Behavioral signatures
   - Automation indicators

5. **Gap Analysis**
   - Missing log sources
   - Timeline gaps
   - Recommended additional data

6. **Incident Narrative**
   - Complete story of the incident
   - Key decision points
   - Impact assessment

Focus on establishing clear causal relationships between events.
""".strip(),
            required_fields=["log_data", "time_window"],
            optional_fields=["systems", "initial_indicators"],
            description="Advanced log correlation for incident reconstruction",
            example_context={
                "time_window": "6_hours",
                "systems": ["firewall", "endpoint", "domain_controller"],
            },
        )

        # Pattern Analysis Templates
        self.templates["pattern_discovery"] = PromptTemplate(
            name="pattern_discovery",
            category=PromptCategory.PATTERN_ANALYSIS,
            analysis_type=AIAnalysisType.PATTERN_ANALYSIS,
            complexity=PromptComplexity.EXPERT,
            template="""
Discover and analyze patterns in the following log data:

<log_dataset>
{log_data}
</log_dataset>

<analysis_parameters>
Pattern types of interest: {pattern_types}
Time granularity: {time_granularity}
Minimum pattern frequency: {min_frequency}
Analysis scope: {scope}
</analysis_parameters>

Conduct comprehensive pattern analysis:

1. **Frequency Patterns**
   - High-frequency event patterns
   - Periodic or cyclical patterns
   - Burst patterns and anomalies

2. **Temporal Patterns**
   - Time-of-day patterns
   - Day-of-week variations
   - Seasonal trends

3. **Behavioral Patterns**
   - User behavior patterns
   - System usage patterns
   - Application interaction patterns

4. **Sequence Patterns**
   - Common event sequences
   - State transition patterns
   - Workflow patterns

5. **Correlation Patterns**
   - Cross-system correlations
   - Multi-source patterns
   - Dependency patterns

6. **Predictive Insights**
   - Trend projections
   - Capacity planning insights
   - Risk forecasting

7. **Security Implications**
   - Attack patterns
   - Reconnaissance signatures
   - Persistence indicators

Provide statistical significance and actionable recommendations.
""".strip(),
            required_fields=["log_data"],
            optional_fields=[
                "pattern_types",
                "time_granularity",
                "min_frequency",
                "scope",
            ],
            description="Advanced pattern discovery and analysis with predictive insights",
            example_context={
                "pattern_types": "authentication,network,file_access",
                "time_granularity": "hourly",
                "min_frequency": "10_occurrences",
            },
        )

        # Incident Summary Templates
        self.templates["incident_executive_summary"] = PromptTemplate(
            name="incident_executive_summary",
            category=PromptCategory.INCIDENT_SUMMARY,
            analysis_type=AIAnalysisType.INCIDENT_SUMMARY,
            complexity=PromptComplexity.DETAILED,
            template="""
Create an executive incident summary from the following security data:

<incident_data>
{log_data}
</incident_data>

<incident_context>
Detection time: {detection_time}
Incident duration: {incident_duration}
Affected systems: {affected_systems}
Business impact: {business_impact}
Response actions taken: {response_actions}
</incident_context>

Provide a comprehensive executive summary:

1. **Executive Overview**
   - Incident classification and severity
   - High-level impact summary
   - Current status

2. **Timeline of Events**
   - Key timestamps and milestones
   - Attack progression
   - Response timeline

3. **Technical Summary**
   - Attack vectors used
   - Systems compromised
   - Data potentially affected

4. **Business Impact**
   - Operational disruption
   - Financial implications
   - Reputation/compliance risks

5. **Response Effectiveness**
   - Detection time analysis
   - Response time assessment
   - Containment effectiveness

6. **Root Cause Analysis**
   - Initial attack vector
   - Security control failures
   - Contributing factors

7. **Lessons Learned**
   - Process improvements needed
   - Technology gaps identified
   - Training requirements

8. **Remediation Plan**
   - Immediate actions completed
   - Ongoing remediation tasks
   - Long-term improvements

Format for executive audience with clear action items.
""".strip(),
            required_fields=["log_data"],
            optional_fields=[
                "detection_time",
                "incident_duration",
                "affected_systems",
                "business_impact",
                "response_actions",
            ],
            description="Executive-level incident summary with business impact assessment",
            example_context={
                "detection_time": "2024-01-15 14:30",
                "incident_duration": "4_hours",
                "affected_systems": "email_server,file_shares",
            },
        )

        # Compliance Check Templates
        self.templates["compliance_audit"] = PromptTemplate(
            name="compliance_audit",
            category=PromptCategory.COMPLIANCE_CHECK,
            analysis_type=AIAnalysisType.SECURITY_EVENT,
            complexity=PromptComplexity.DETAILED,
            template="""
Perform compliance analysis on the following log data:

<audit_logs>
{log_data}
</audit_logs>

<compliance_framework>
Standards: {compliance_standards}
Requirements: {specific_requirements}
Audit period: {audit_period}
Previous findings: {previous_findings}
</compliance_framework>

Conduct thorough compliance assessment:

1. **Compliance Status**
   - Overall compliance score
   - Standards compliance summary
   - Critical violations identified

2. **Access Control Analysis**
   - User access patterns
   - Privileged access usage
   - Authorization compliance

3. **Data Protection Assessment**
   - Data access logging
   - Encryption compliance
   - Data retention policies

4. **Audit Trail Evaluation**
   - Log completeness
   - Audit trail integrity
   - Monitoring coverage

5. **Policy Violations**
   - Security policy breaches
   - Usage policy violations
   - Procedural non-compliance

6. **Risk Assessment**
   - Compliance risks identified
   - Impact of violations
   - Remediation priorities

7. **Recommendations**
   - Immediate corrective actions
   - Process improvements
   - Technical controls needed

Map findings to specific compliance requirements.
""".strip(),
            required_fields=["log_data", "compliance_standards"],
            optional_fields=[
                "specific_requirements",
                "audit_period",
                "previous_findings",
            ],
            description="Comprehensive compliance analysis against industry standards",
            example_context={
                "compliance_standards": "SOX,PCI-DSS,ISO27001",
                "audit_period": "Q4_2024",
            },
        )

    def get_template(self, template_name: str) -> Optional[PromptTemplate]:
        """Get a specific template by name

        Args:
            template_name: Name of the template

        Returns:
            Template if found, None otherwise
        """
        return self.templates.get(template_name)

    def list_templates(
        self,
        category: Optional[PromptCategory] = None,
        analysis_type: Optional[AIAnalysisType] = None,
        complexity: Optional[PromptComplexity] = None,
    ) -> List[PromptTemplate]:
        """List available templates with optional filters

        Args:
            category: Filter by category
            analysis_type: Filter by analysis type
            complexity: Filter by complexity level

        Returns:
            List of matching templates
        """
        templates = list(self.templates.values())

        if category:
            templates = [t for t in templates if t.category == category]

        if analysis_type:
            templates = [t for t in templates if t.analysis_type == analysis_type]

        if complexity:
            templates = [t for t in templates if t.complexity == complexity]

        return templates

    def format_prompt(
        self, template_name: str, data: Dict[str, Any], validate_fields: bool = True
    ) -> str:
        """Format a prompt template with provided data

        Args:
            template_name: Name of the template
            data: Data to fill template placeholders
            validate_fields: Whether to validate required fields

        Returns:
            Formatted prompt string

        Raises:
            KeyError: If required fields are missing
            ValueError: If template not found
        """
        template = self.templates.get(template_name)
        if not template:
            raise ValueError(f"Template '{template_name}' not found")

        # Validate required fields
        if validate_fields:
            missing_fields = [
                field for field in template.required_fields if field not in data
            ]
            if missing_fields:
                raise KeyError(f"Missing required fields: {missing_fields}")

        # Format template with data
        try:
            # Handle missing optional fields
            format_data = data.copy()
            for field in template.optional_fields:
                if field not in format_data:
                    format_data[field] = "Not specified"

            # Format JSON data nicely
            for key, value in format_data.items():
                if isinstance(value, (dict, list)):
                    format_data[key] = json.dumps(value, indent=2)
                elif value is None:
                    format_data[key] = "Not provided"

            formatted_prompt = template.template.format(**format_data)
            return formatted_prompt

        except KeyError as e:
            raise KeyError(f"Template formatting error: {e}")

    def create_custom_prompt(
        self,
        analysis_type: AIAnalysisType,
        log_data: Any,
        context: Optional[Dict[str, Any]] = None,
        instructions: Optional[List[str]] = None,
        complexity: PromptComplexity = PromptComplexity.DETAILED,
    ) -> str:
        """Create a custom prompt for log analysis

        Args:
            analysis_type: Type of analysis to perform
            log_data: Log data to analyze
            context: Additional context information
            instructions: Specific instructions for analysis
            complexity: Complexity level of analysis

        Returns:
            Custom formatted prompt
        """
        # Base system instruction
        system_instructions = {
            AIAnalysisType.SECURITY_EVENT: (
                "You are a cybersecurity expert analyzing security logs. "
                "Focus on threat identification and risk assessment."
            ),
            AIAnalysisType.ANOMALY_DETECTION: (
                "You are an anomaly detection specialist. "
                "Identify unusual patterns and deviations from normal behavior."
            ),
            AIAnalysisType.THREAT_CLASSIFICATION: (
                "You are a threat intelligence analyst. "
                "Classify threats using industry frameworks and provide IOCs."
            ),
            AIAnalysisType.LOG_CORRELATION: (
                "You are a log correlation expert. "
                "Analyze relationships between events and reconstruct incident timelines."
            ),
            AIAnalysisType.PATTERN_ANALYSIS: (
                "You are a pattern analysis specialist. "
                "Discover trends and behavioral patterns in log data."
            ),
            AIAnalysisType.INCIDENT_SUMMARY: (
                "You are an incident response analyst. "
                "Create comprehensive incident summaries with actionable recommendations."
            ),
        }

        # Format log data
        if isinstance(log_data, (dict, list)):
            formatted_data = json.dumps(log_data, indent=2)
        else:
            formatted_data = str(log_data)

        # Build prompt based on complexity
        if complexity == PromptComplexity.SIMPLE:
            prompt = f"""
{system_instructions.get(analysis_type, 'You are a log analysis expert.')}

Analyze the following log data:

{formatted_data}

Context: {json.dumps(context, indent=2) if context else 'None provided'}

Provide a concise analysis with key findings and recommendations.
"""

        elif complexity == PromptComplexity.DETAILED:
            prompt = f"""
{system_instructions.get(analysis_type, 'You are a log analysis expert.')}

Please perform a detailed analysis of the following log data:

<log_data>
{formatted_data}
</log_data>

<context>
{json.dumps(context, indent=2) if context else 'No additional context provided'}
</context>

Please provide a comprehensive analysis including:

1. Summary: Overview of key findings
2. Detailed Analysis: In-depth examination
3. Risk Assessment: Security and operational risks
4. Evidence: Specific log entries supporting conclusions
5. Recommendations: Actionable next steps
6. Confidence: Your confidence level in the analysis

{self._format_custom_instructions(instructions)}
"""

        else:  # EXPERT
            prompt = f"""
{system_instructions.get(analysis_type, 'You are a log analysis expert.')}

Conduct an expert-level analysis of the following log data using advanced methodologies:

<log_data>
{formatted_data}
</log_data>

<context>
{json.dumps(context, indent=2) if context else 'No additional context provided'}
</context>

Provide a comprehensive expert analysis including:

1. Executive Summary: High-level findings and impact
2. Methodology: Analysis approach and techniques used
3. Technical Analysis: Deep technical examination
4. Statistical Analysis: Quantitative measures and significance
5. Risk Assessment: Detailed risk evaluation with likelihood
6. Evidence Chain: Complete evidence trail with references
7. Attribution: Threat actor or root cause assessment
8. Recommendations: Strategic and tactical recommendations
9. Confidence Assessment: Detailed confidence analysis
10. Further Investigation: Additional data sources or analysis needed

{self._format_custom_instructions(instructions)}

Use industry-standard frameworks and provide quantitative measures where possible.
"""

        return prompt.strip()

    def _format_custom_instructions(self, instructions: Optional[List[str]]) -> str:
        """Format custom instructions for prompt

        Args:
            instructions: List of custom instructions

        Returns:
            Formatted instructions string
        """
        if not instructions:
            return ""

        formatted = "Additional Instructions:\n"
        for i, instruction in enumerate(instructions, 1):
            formatted += f"{i}. {instruction}\n"

        return formatted

    def suggest_template(
        self,
        analysis_type: AIAnalysisType,
        data_characteristics: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """Suggest appropriate templates based on analysis type and data characteristics

        Args:
            analysis_type: Type of analysis needed
            data_characteristics: Characteristics of the data to analyze

        Returns:
            List of recommended template names
        """
        matching_templates = [
            t.name for t in self.templates.values() if t.analysis_type == analysis_type
        ]

        if not matching_templates:
            # Return generic templates that might work
            return ["security_basic", "anomaly_basic"]

        # Sort by complexity - start with detailed, then simple, then expert
        complexity_order = {
            PromptComplexity.DETAILED: 1,
            PromptComplexity.SIMPLE: 2,
            PromptComplexity.EXPERT: 3,
        }

        template_objects = [self.templates[name] for name in matching_templates]
        sorted_templates = sorted(
            template_objects, key=lambda t: complexity_order.get(t.complexity, 4)
        )

        return [t.name for t in sorted_templates]

    def validate_template_data(
        self, template_name: str, data: Dict[str, Any]
    ) -> Dict[str, List[str]]:
        """Validate data against template requirements

        Args:
            template_name: Name of the template
            data: Data to validate

        Returns:
            Dict with 'missing_required' and 'available_optional' keys
        """
        template = self.templates.get(template_name)
        if not template:
            return {
                "missing_required": ["Template not found"],
                "available_optional": [],
            }

        missing_required = [
            field for field in template.required_fields if field not in data
        ]

        available_optional = [
            field for field in template.optional_fields if field in data
        ]

        return {
            "missing_required": missing_required,
            "available_optional": available_optional,
        }

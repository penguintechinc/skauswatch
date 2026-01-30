"""Marshmallow schemas for security finding validation and serialization."""

from marshmallow import Schema, fields, validate


class FindingResponseSchema(Schema):
    """Schema for finding response serialization."""

    id = fields.Integer()
    job_id = fields.Integer()
    target_id = fields.Integer()
    finding_id = fields.String(allow_none=True)
    severity = fields.String()
    title = fields.String()
    description = fields.String()
    remediation = fields.String()
    affected_url = fields.String()
    cvss_score = fields.Float()
    cve_ids = fields.List(fields.String())
    cwe_ids = fields.List(fields.String())
    evidence = fields.String()
    raw_finding = fields.Dict()
    status = fields.String()
    discovered_at = fields.DateTime(format="iso")
    updated_at = fields.DateTime(format="iso")


class UpdateFindingSchema(Schema):
    """Schema for updating a finding (e.g., marking as false positive or fixed)."""

    status = fields.String(
        required=True,
        validate=validate.OneOf(["open", "acknowledged", "false_positive", "fixed"]),
    )


class FindingFilterSchema(Schema):
    """Schema for filtering and querying findings."""

    severity = fields.String(
        validate=validate.OneOf(["critical", "high", "medium", "low", "info"])
    )
    status = fields.String(
        validate=validate.OneOf(["open", "acknowledged", "false_positive", "fixed"])
    )
    scanner_type = fields.String(
        validate=validate.OneOf(["nuclei", "zap", "openvas"])
    )
    target_id = fields.Integer()
    job_id = fields.Integer()
    page = fields.Integer(load_default=1, validate=validate.Range(min=1))
    per_page = fields.Integer(load_default=20, validate=validate.Range(min=1, max=100))


class FindingStatsSchema(Schema):
    """Schema for finding statistics response."""

    total = fields.Integer()
    by_severity = fields.Dict(keys=fields.String(), values=fields.Integer())
    by_status = fields.Dict(keys=fields.String(), values=fields.Integer())
    by_scanner = fields.Dict(keys=fields.String(), values=fields.Integer())


class FindingExportSchema(Schema):
    """Schema for finding export request."""

    format = fields.String(required=True, validate=validate.OneOf(["json", "csv"]))
    severity = fields.List(
        fields.String(validate=validate.OneOf(["critical", "high", "medium", "low", "info"])),
        load_default=[],
    )
    status = fields.List(
        fields.String(validate=validate.OneOf(["open", "acknowledged", "false_positive", "fixed"])),
        load_default=[],
    )
    target_id = fields.Integer()
    job_id = fields.Integer()

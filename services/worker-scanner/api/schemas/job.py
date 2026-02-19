"""Marshmallow schemas for scan job validation and serialization."""

from marshmallow import Schema, fields, validate


class CreateJobSchema(Schema):
    """Schema for creating a new scan job."""

    target_id = fields.Integer(required=True)
    scanner_type = fields.String(
        required=True, validate=validate.OneOf(["nuclei", "zap", "openvas"])
    )
    scan_type = fields.String(
        required=True,
        validate=validate.OneOf(
            [
                "baseline",
                "full",
                "api",
                "custom",
                "discovery",
                "full_and_fast",
                "full_and_deep",
            ]
        ),
    )
    priority = fields.Integer(load_default=5, validate=validate.Range(min=1, max=10))
    config = fields.Dict(load_default={})


class JobResponseSchema(Schema):
    """Schema for job response serialization."""

    id = fields.Integer()
    target_id = fields.Integer()
    scanner_type = fields.String()
    scan_type = fields.String()
    status = fields.String()
    priority = fields.Integer()
    config = fields.Dict()
    started_at = fields.DateTime(format="iso", allow_none=True)
    completed_at = fields.DateTime(format="iso", allow_none=True)
    duration_seconds = fields.Integer(allow_none=True)
    error_message = fields.String(allow_none=True)
    result_summary = fields.Dict(allow_none=True)
    created_at = fields.DateTime(format="iso")
    created_by = fields.String(allow_none=True)


class JobFilterSchema(Schema):
    """Schema for filtering and querying jobs."""

    status = fields.String(
        validate=validate.OneOf(
            ["pending", "running", "completed", "failed", "cancelled"]
        )
    )
    scanner_type = fields.String(validate=validate.OneOf(["nuclei", "zap", "openvas"]))
    target_id = fields.Integer()
    page = fields.Integer(load_default=1, validate=validate.Range(min=1))
    per_page = fields.Integer(load_default=20, validate=validate.Range(min=1, max=100))

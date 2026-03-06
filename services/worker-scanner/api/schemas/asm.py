"""Marshmallow schemas for ASM (Attack Surface Management) API endpoints."""

from marshmallow import Schema, ValidationError, fields, validate, validates


class AsmScanCreateSchema(Schema):
    """Schema for creating an ASM scan."""

    target_id = fields.Int(required=True)
    mode = fields.Str(
        load_default="external",
        validate=validate.OneOf(["internal", "external", "both"]),
    )
    extra_ports = fields.List(fields.Int(), load_default=[])
    rate = fields.Int(load_default=1000, validate=validate.Range(min=1, max=1000000))

    @validates("extra_ports")
    def validate_ports(self, value):
        for port in value:
            if not (1 <= port <= 65535):
                raise ValidationError(f"Invalid port: {port}")


class PortsConfigSchema(Schema):
    """Schema for port configuration settings."""

    extra_ports = fields.List(
        fields.Int(validate=validate.Range(min=1, max=65535)),
        load_default=[],
    )
    masscan_rate = fields.Int(load_default=1000, validate=validate.Range(min=1, max=1000000))


class AsmScanResponseSchema(Schema):
    """Schema for ASM scan response."""

    id = fields.Int()
    target_id = fields.Int()
    mode = fields.Str()
    status = fields.Str()
    ports_config = fields.Dict()
    created_at = fields.DateTime()
    started_at = fields.DateTime(allow_none=True)
    completed_at = fields.DateTime(allow_none=True)
    created_by = fields.Str(allow_none=True)


class AsmHostResponseSchema(Schema):
    """Schema for ASM host response."""

    id = fields.Int()
    scan_id = fields.Int()
    ip_address = fields.Str()
    hostname = fields.Str(allow_none=True)
    is_alive = fields.Bool()
    latency_ms = fields.Float(allow_none=True)
    os_guess = fields.Str(allow_none=True)
    created_at = fields.DateTime()


class AsmServiceResponseSchema(Schema):
    """Schema for ASM service (open port) response."""

    id = fields.Int()
    host_id = fields.Int()
    port = fields.Int()
    protocol = fields.Str()
    state = fields.Str()
    service_name = fields.Str(allow_none=True)
    banner = fields.Str(allow_none=True)
    version = fields.Str(allow_none=True)
    created_at = fields.DateTime()


class AsmScreenshotResponseSchema(Schema):
    """Schema for ASM screenshot response."""

    id = fields.Int()
    service_id = fields.Int()
    s3_key = fields.Str()
    presigned_url = fields.Str(allow_none=True)
    url = fields.Str(allow_none=True)
    tool = fields.Str()
    file_size_bytes = fields.Int(allow_none=True)
    captured_at = fields.DateTime(allow_none=True)
    created_at = fields.DateTime()


class AsmCertResponseSchema(Schema):
    """Schema for ASM certificate response."""

    id = fields.Int()
    service_id = fields.Int()
    subject = fields.Str(allow_none=True)
    issuer = fields.Str(allow_none=True)
    not_before = fields.DateTime(allow_none=True)
    not_after = fields.DateTime(allow_none=True)
    is_expired = fields.Bool()
    days_until_expiry = fields.Int(allow_none=True)
    sans = fields.List(fields.Str(), allow_none=True)
    fingerprint_sha256 = fields.Str(allow_none=True)
    created_at = fields.DateTime()


class AsmDiffResponseSchema(Schema):
    """Schema for ASM diff response."""

    id = fields.Int()
    scan_id = fields.Int()
    prev_scan_id = fields.Int(allow_none=True)
    new_services = fields.List(fields.Dict(), allow_none=True)
    removed_services = fields.List(fields.Dict(), allow_none=True)
    new_certs = fields.List(fields.Dict(), allow_none=True)
    expired_certs = fields.List(fields.Dict(), allow_none=True)
    created_at = fields.DateTime()

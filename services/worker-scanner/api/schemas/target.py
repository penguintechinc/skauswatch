"""Marshmallow schemas for scan target validation and serialization."""

from marshmallow import Schema, fields, validate, validates_schema, ValidationError

from utils.validators import validate_target_value


class CreateTargetSchema(Schema):
    """Schema for creating a new scan target."""

    name = fields.String(required=True, validate=validate.Length(min=1, max=255))
    target_type = fields.String(
        required=True, validate=validate.OneOf(["domain", "ip", "url", "cidr"])
    )
    target_value = fields.String(
        required=True, validate=validate.Length(min=1, max=2048)
    )
    description = fields.String(load_default="", validate=validate.Length(max=5000))
    enabled = fields.Boolean(load_default=True)
    tags = fields.List(fields.String(), load_default=[])
    metadata = fields.Dict(load_default={})

    @validates_schema
    def validate_target_value_against_type(self, data, **kwargs):
        """Validate target_value against target_type for format compatibility."""
        target_type = data.get("target_type")
        target_value = data.get("target_value")

        if target_type and target_value:
            is_valid, error_message = validate_target_value(target_type, target_value)
            if not is_valid:
                raise ValidationError(
                    {"target_value": error_message},
                    field_name="target_value",
                )


class UpdateTargetSchema(Schema):
    """Schema for updating a scan target."""

    name = fields.String(validate=validate.Length(min=1, max=255))
    target_type = fields.String(
        validate=validate.OneOf(["domain", "ip", "url", "cidr"])
    )
    target_value = fields.String(validate=validate.Length(min=1, max=2048))
    description = fields.String(validate=validate.Length(max=5000))
    enabled = fields.Boolean()
    tags = fields.List(fields.String())
    metadata = fields.Dict()

    @validates_schema
    def validate_target_value_against_type(self, data, **kwargs):
        """Validate target_value against target_type for format compatibility."""
        target_type = data.get("target_type")
        target_value = data.get("target_value")

        if target_type and target_value:
            is_valid, error_message = validate_target_value(target_type, target_value)
            if not is_valid:
                raise ValidationError(
                    {"target_value": error_message},
                    field_name="target_value",
                )


class TargetResponseSchema(Schema):
    """Schema for target response serialization."""

    id = fields.Integer()
    name = fields.String()
    target_type = fields.String()
    target_value = fields.String()
    description = fields.String()
    enabled = fields.Boolean()
    tags = fields.List(fields.String())
    metadata = fields.Dict()
    created_at = fields.DateTime(format="iso")
    updated_at = fields.DateTime(format="iso")
    created_by = fields.String()

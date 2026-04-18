"""pytest tests for scim/mappers.py — 100% coverage of SCIM conversion functions."""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from scim import mappers


class TestUserToScim:
    """Test user_to_scim conversion function."""

    def test_basic_user_conversion(self, user_record: SimpleNamespace) -> None:
        """Test converting a basic user record to SCIM format."""
        result = mappers.user_to_scim(user_record, base_url="https://example.com/scim/v2")

        assert result["schemas"] == [mappers.SCIM_USER_SCHEMA]
        assert result["id"] == "user-123"
        assert result["externalId"] == "user-123"
        assert result["userName"] == "jdoe"
        assert result["displayName"] == "John Doe"
        assert result["active"] is True
        assert result["meta"]["resourceType"] == "User"
        assert result["meta"]["location"] == "https://example.com/scim/v2/Users/user-123"

    def test_user_name_parsing_full(self, user_record: SimpleNamespace) -> None:
        """Test name parsing with both given and family names."""
        result = mappers.user_to_scim(user_record)

        assert result["name"]["formatted"] == "John Doe"
        assert result["name"]["givenName"] == "John"
        assert result["name"]["familyName"] == "Doe"

    def test_user_name_parsing_single_name(self) -> None:
        """Test name parsing with single name (no family name)."""
        user = SimpleNamespace(
            uuid="u1",
            username="cher",
            email="cher@example.com",
            display_name="Cher",
            is_active=True,
            groups=[],
            attributes={},
        )
        result = mappers.user_to_scim(user)

        assert result["name"]["formatted"] == "Cher"
        assert result["name"]["givenName"] == "Cher"
        assert result["name"]["familyName"] == ""

    def test_user_name_parsing_empty_display(self) -> None:
        """Test name parsing with empty display_name."""
        user = SimpleNamespace(
            uuid="u1",
            username="noname",
            email="noname@example.com",
            display_name="",
            is_active=True,
            groups=[],
            attributes={},
        )
        result = mappers.user_to_scim(user)

        assert result["name"]["formatted"] == ""
        assert result["name"]["givenName"] == ""
        assert result["name"]["familyName"] == ""

    def test_user_name_parsing_none_display(self) -> None:
        """Test name parsing when display_name is None."""
        user = SimpleNamespace(
            uuid="u1",
            username="noname",
            email="noname@example.com",
            display_name=None,
            is_active=True,
            groups=[],
            attributes={},
        )
        result = mappers.user_to_scim(user)

        assert result["name"]["formatted"] == ""
        assert result["name"]["givenName"] == ""
        assert result["name"]["familyName"] == ""

    def test_user_email_primary(self, user_record: SimpleNamespace) -> None:
        """Test email field is marked as primary and work type."""
        result = mappers.user_to_scim(user_record)

        assert len(result["emails"]) == 1
        assert result["emails"][0]["value"] == "jdoe@example.com"
        assert result["emails"][0]["primary"] is True
        assert result["emails"][0]["type"] == "work"

    def test_user_active_true(self, user_record: SimpleNamespace) -> None:
        """Test active field when user is active."""
        result = mappers.user_to_scim(user_record)
        assert result["active"] is True

    def test_user_active_false(self, inactive_user_record: SimpleNamespace) -> None:
        """Test active field when user is inactive."""
        result = mappers.user_to_scim(inactive_user_record)
        assert result["active"] is False

    def test_user_groups_populated(self, user_record: SimpleNamespace) -> None:
        """Test groups list is populated correctly."""
        result = mappers.user_to_scim(user_record)

        assert len(result["groups"]) == 2
        assert result["groups"][0] == {"value": "group-1", "display": "group-1"}
        assert result["groups"][1] == {"value": "group-2", "display": "group-2"}

    def test_user_groups_empty(self) -> None:
        """Test groups when list is empty."""
        user = SimpleNamespace(
            uuid="u1",
            username="nogroups",
            email="nogroups@example.com",
            display_name="No Groups",
            is_active=True,
            groups=[],
            attributes={},
        )
        result = mappers.user_to_scim(user)
        assert result["groups"] == []

    def test_user_groups_none(self) -> None:
        """Test groups when attribute is None."""
        user = SimpleNamespace(
            uuid="u1",
            username="nogroups",
            email="nogroups@example.com",
            display_name="No Groups",
            is_active=True,
            groups=None,
            attributes={},
        )
        result = mappers.user_to_scim(user)
        assert result["groups"] == []

    def test_user_custom_attributes_present(self, user_record: SimpleNamespace) -> None:
        """Test custom attributes are included in enterprise extension."""
        result = mappers.user_to_scim(user_record)

        ext_key = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        assert ext_key in result
        assert result[ext_key]["department"] == "engineering"
        assert result[ext_key]["location"] == "sf"

    def test_user_custom_attributes_none(self) -> None:
        """Test when attributes dict is None."""
        user = SimpleNamespace(
            uuid="u1",
            username="noattrs",
            email="noattrs@example.com",
            display_name="No Attrs",
            is_active=True,
            groups=[],
            attributes=None,
        )
        result = mappers.user_to_scim(user)

        ext_key = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        assert ext_key not in result

    def test_user_custom_attributes_empty(self) -> None:
        """Test when attributes dict is empty."""
        user = SimpleNamespace(
            uuid="u1",
            username="emptyattrs",
            email="emptyattrs@example.com",
            display_name="Empty Attrs",
            is_active=True,
            groups=[],
            attributes={},
        )
        result = mappers.user_to_scim(user)

        ext_key = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        assert ext_key not in result

    def test_user_location_url_construction(self, user_record: SimpleNamespace) -> None:
        """Test meta.location URL is constructed correctly with base_url."""
        result = mappers.user_to_scim(user_record, base_url="https://idp.example.org/scim")
        assert result["meta"]["location"] == "https://idp.example.org/scim/Users/user-123"

    def test_user_location_url_strips_trailing_slash(self, user_record: SimpleNamespace) -> None:
        """Test base_url trailing slash is removed."""
        result = mappers.user_to_scim(user_record, base_url="https://idp.example.org/scim/")
        assert result["meta"]["location"] == "https://idp.example.org/scim/Users/user-123"

    def test_user_location_empty_base_url(self, user_record: SimpleNamespace) -> None:
        """Test location when base_url is empty string."""
        result = mappers.user_to_scim(user_record, base_url="")
        assert result["meta"]["location"] == "/Users/user-123"


class TestGroupToScim:
    """Test group_to_scim conversion function."""

    def test_basic_group_conversion(self, group_record: SimpleNamespace) -> None:
        """Test converting a basic group record to SCIM format."""
        result = mappers.group_to_scim(group_record, base_url="https://example.com/scim/v2")

        assert result["schemas"] == [mappers.SCIM_GROUP_SCHEMA]
        assert result["id"] == "group-789"
        assert result["externalId"] == "group-789"
        assert result["displayName"] == "Engineering Team"
        assert result["meta"]["resourceType"] == "Group"
        assert result["meta"]["location"] == "https://example.com/scim/v2/Groups/group-789"

    def test_group_members_populated(
        self, group_record: SimpleNamespace, member_records: list[SimpleNamespace]
    ) -> None:
        """Test members list is populated correctly."""
        result = mappers.group_to_scim(
            group_record, members=member_records, base_url="https://example.com/scim/v2"
        )

        assert len(result["members"]) == 2
        assert result["members"][0]["value"] == "user-001"
        assert result["members"][0]["display"] == "Alice"
        assert result["members"][0]["$ref"] == "https://example.com/scim/v2/Users/user-001"
        assert result["members"][1]["value"] == "user-002"
        assert result["members"][1]["display"] == "Bob Chen"
        assert result["members"][1]["$ref"] == "https://example.com/scim/v2/Users/user-002"

    def test_group_members_empty(self, group_record: SimpleNamespace) -> None:
        """Test members when list is empty."""
        result = mappers.group_to_scim(group_record, members=[])
        assert result["members"] == []

    def test_group_members_none(self, group_record: SimpleNamespace) -> None:
        """Test members when not provided."""
        result = mappers.group_to_scim(group_record, members=None)
        assert result["members"] == []

    def test_group_member_display_fallback(
        self, group_record: SimpleNamespace
    ) -> None:
        """Test member display falls back to username when display_name is None."""
        member = SimpleNamespace(
            uuid="u1",
            username="jsmith",
            display_name=None,
            is_active=True,
        )
        result = mappers.group_to_scim(
            group_record, members=[member], base_url="https://example.com/scim/v2"
        )

        assert result["members"][0]["display"] == "jsmith"

    def test_group_member_display_fallback_empty(
        self, group_record: SimpleNamespace
    ) -> None:
        """Test member display falls back to username when display_name is empty."""
        member = SimpleNamespace(
            uuid="u1",
            username="jsmith",
            display_name="",
            is_active=True,
        )
        result = mappers.group_to_scim(
            group_record, members=[member], base_url="https://example.com/scim/v2"
        )

        assert result["members"][0]["display"] == "jsmith"

    def test_group_location_url_construction(self, group_record: SimpleNamespace) -> None:
        """Test meta.location URL is constructed correctly."""
        result = mappers.group_to_scim(group_record, base_url="https://idp.example.org/scim")
        assert result["meta"]["location"] == "https://idp.example.org/scim/Groups/group-789"

    def test_group_location_url_strips_trailing_slash(
        self, group_record: SimpleNamespace
    ) -> None:
        """Test base_url trailing slash is removed."""
        result = mappers.group_to_scim(group_record, base_url="https://idp.example.org/scim/")
        assert result["meta"]["location"] == "https://idp.example.org/scim/Groups/group-789"

    def test_group_location_empty_base_url(self, group_record: SimpleNamespace) -> None:
        """Test location when base_url is empty string."""
        result = mappers.group_to_scim(group_record, base_url="")
        assert result["meta"]["location"] == "/Groups/group-789"


class TestScimToUserFields:
    """Test scim_to_user_fields conversion function."""

    def test_basic_scim_to_user_fields(self) -> None:
        """Test converting basic SCIM user to user fields dict."""
        scim_body = {
            "userName": "jdoe",
            "displayName": "John Doe",
            "emails": [{"value": "jdoe@example.com", "primary": True}],
            "active": True,
        }
        result = mappers.scim_to_user_fields(scim_body)

        assert result["username"] == "jdoe"
        assert result["display_name"] == "John Doe"
        assert result["email"] == "jdoe@example.com"
        assert result["is_active"] is True

    def test_username_extraction(self) -> None:
        """Test userName field is mapped to username."""
        scim_body = {"userName": "alice"}
        result = mappers.scim_to_user_fields(scim_body)
        assert result["username"] == "alice"

    def test_displayname_direct(self) -> None:
        """Test displayName field is mapped directly."""
        scim_body = {"displayName": "Alice Wonder"}
        result = mappers.scim_to_user_fields(scim_body)
        assert result["display_name"] == "Alice Wonder"

    def test_displayname_from_name_formatted(self) -> None:
        """Test displayName extracted from name.formatted."""
        scim_body = {"name": {"formatted": "Alice Wonder"}}
        result = mappers.scim_to_user_fields(scim_body)
        assert result["display_name"] == "Alice Wonder"

    def test_displayname_from_name_parts(self) -> None:
        """Test displayName constructed from given/family names."""
        scim_body = {"name": {"givenName": "Alice", "familyName": "Wonder"}}
        result = mappers.scim_to_user_fields(scim_body)
        assert result["display_name"] == "Alice Wonder"

    def test_displayname_from_name_parts_given_only(self) -> None:
        """Test displayName with only givenName."""
        scim_body = {"name": {"givenName": "Alice"}}
        result = mappers.scim_to_user_fields(scim_body)
        assert result["display_name"] == "Alice"

    def test_displayname_from_name_parts_family_only(self) -> None:
        """Test displayName with only familyName."""
        scim_body = {"name": {"familyName": "Wonder"}}
        result = mappers.scim_to_user_fields(scim_body)
        assert result["display_name"] == "Wonder"

    def test_displayname_priority_formatted_over_parts(self) -> None:
        """Test displayName.formatted takes priority over parts."""
        scim_body = {
            "name": {
                "formatted": "Formatted Name",
                "givenName": "Given",
                "familyName": "Family",
            }
        }
        result = mappers.scim_to_user_fields(scim_body)
        assert result["display_name"] == "Formatted Name"

    def test_displayname_priority_direct_over_name_object(self) -> None:
        """Test direct displayName takes priority over name object."""
        scim_body = {
            "displayName": "Direct",
            "name": {"formatted": "Formatted"},
        }
        result = mappers.scim_to_user_fields(scim_body)
        assert result["display_name"] == "Direct"

    def test_email_primary_preferred(self) -> None:
        """Test primary email is preferred."""
        scim_body = {
            "emails": [
                {"value": "secondary@example.com", "primary": False},
                {"value": "primary@example.com", "primary": True},
            ]
        }
        result = mappers.scim_to_user_fields(scim_body)
        assert result["email"] == "primary@example.com"

    def test_email_first_when_no_primary(self) -> None:
        """Test first email is used when no primary."""
        scim_body = {"emails": [{"value": "first@example.com"}, {"value": "second@example.com"}]}
        result = mappers.scim_to_user_fields(scim_body)
        assert result["email"] == "first@example.com"

    def test_email_empty_list(self) -> None:
        """Test empty email list."""
        scim_body = {"emails": []}
        result = mappers.scim_to_user_fields(scim_body)
        assert "email" not in result

    def test_email_not_list(self) -> None:
        """Test when emails is not a list."""
        scim_body = {"emails": "not-a-list"}
        result = mappers.scim_to_user_fields(scim_body)
        assert "email" not in result

    def test_active_true(self) -> None:
        """Test active field true."""
        scim_body = {"active": True}
        result = mappers.scim_to_user_fields(scim_body)
        assert result["is_active"] is True

    def test_active_false(self) -> None:
        """Test active field false."""
        scim_body = {"active": False}
        result = mappers.scim_to_user_fields(scim_body)
        assert result["is_active"] is False

    def test_active_truthy_values(self) -> None:
        """Test active field with truthy non-boolean."""
        scim_body = {"active": "yes"}
        result = mappers.scim_to_user_fields(scim_body)
        assert result["is_active"] is True

    def test_active_falsy_values(self) -> None:
        """Test active field with falsy value."""
        scim_body = {"active": 0}
        result = mappers.scim_to_user_fields(scim_body)
        assert result["is_active"] is False

    def test_password_extraction(self) -> None:
        """Test password field is extracted."""
        scim_body = {"password": "SecurePass123"}
        result = mappers.scim_to_user_fields(scim_body)
        assert result["password"] == "SecurePass123"

    def test_unknown_fields_ignored(self) -> None:
        """Test unknown SCIM fields are ignored."""
        scim_body = {
            "userName": "jdoe",
            "unknownField": "should be ignored",
            "anotherUnknown": {"nested": "value"},
        }
        result = mappers.scim_to_user_fields(scim_body)

        assert "unknownField" not in result
        assert "anotherUnknown" not in result
        assert result["username"] == "jdoe"

    def test_empty_body(self) -> None:
        """Test with empty SCIM body."""
        result = mappers.scim_to_user_fields({})
        assert result == {}

    def test_patch_operation_payload(self) -> None:
        """Test with PATCH operation subset of fields."""
        scim_body = {"userName": "newusername", "active": False}
        result = mappers.scim_to_user_fields(scim_body)

        assert result["username"] == "newusername"
        assert result["is_active"] is False
        assert "email" not in result


class TestScimError:
    """Test scim_error helper function."""

    def test_error_basic(self) -> None:
        """Test basic error response."""
        result = mappers.scim_error(400, "Invalid input")

        assert result["schemas"] == [mappers.SCIM_ERROR_SCHEMA]
        assert result["status"] == "400"
        assert result["detail"] == "Invalid input"
        assert "scimType" not in result

    def test_error_with_scim_type(self) -> None:
        """Test error with scimType."""
        result = mappers.scim_error(409, "Resource conflict", "uniqueness")

        assert result["status"] == "409"
        assert result["detail"] == "Resource conflict"
        assert result["scimType"] == "uniqueness"

    def test_error_status_string_conversion(self) -> None:
        """Test status is converted to string."""
        result = mappers.scim_error(500, "Internal error")
        assert isinstance(result["status"], str)
        assert result["status"] == "500"

    def test_error_empty_scim_type(self) -> None:
        """Test empty scimType is not included."""
        result = mappers.scim_error(400, "Bad request", "")
        assert "scimType" not in result


class TestScimListResponse:
    """Test scim_list_response helper function."""

    def test_list_response_basic(self) -> None:
        """Test basic list response."""
        resources = [
            {"id": "user-1", "userName": "user1"},
            {"id": "user-2", "userName": "user2"},
        ]
        result = mappers.scim_list_response(resources, total_results=10)

        assert result["schemas"] == [mappers.SCIM_LIST_RESPONSE_SCHEMA]
        assert result["totalResults"] == 10
        assert result["startIndex"] == 1
        assert result["itemsPerPage"] == 2
        assert result["Resources"] == resources

    def test_list_response_custom_start_index(self) -> None:
        """Test list response with custom start index."""
        resources = [{"id": "user-3"}]
        result = mappers.scim_list_response(resources, total_results=100, start_index=21)

        assert result["startIndex"] == 21
        assert result["itemsPerPage"] == 1

    def test_list_response_empty(self) -> None:
        """Test list response with no resources."""
        result = mappers.scim_list_response([], total_results=0)

        assert result["totalResults"] == 0
        assert result["itemsPerPage"] == 0
        assert result["Resources"] == []

    def test_list_response_items_per_page_matches_length(self) -> None:
        """Test itemsPerPage equals actual resource count."""
        resources = [{"id": f"user-{i}"} for i in range(5)]
        result = mappers.scim_list_response(resources, total_results=50)

        assert result["itemsPerPage"] == len(resources)

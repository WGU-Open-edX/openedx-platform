"""
Tests for the AuthZ enforcement of the Instructor Dashboard API v2.

They cover the tabs, ``authz_permissions`` and the migrated endpoints.
"""

from unittest.mock import patch

import ddt
from django.contrib.auth import get_user_model
from django.urls import reverse
from openedx_authz.constants.roles import COURSE_ADMIN, COURSE_STAFF
from rest_framework import status
from rest_framework.test import APIClient

from common.djangoapps.student.roles import CourseInstructorRole, CourseStaffRole
from common.djangoapps.student.tests.factories import (
    InstructorFactory,
    StaffFactory,
    UserFactory,
)
from lms.djangoapps.courseware.tabs import get_course_tab_list
from lms.djangoapps.instructor.authz import constants
from lms.djangoapps.instructor.authz.tests.mixins import InstructorAuthzTestMixin
from openedx.core.djangoapps.django_comment_common.models import (
    FORUM_ROLE_ADMINISTRATOR,
    FORUM_ROLE_MODERATOR,
    Role,
)
from openedx.core.djangoapps.django_comment_common.utils import seed_permissions_roles
from xmodule.modulestore.tests.django_utils import SharedModuleStoreTestCase
from xmodule.modulestore.tests.factories import CourseFactory

API = "lms.djangoapps.instructor.authz.api"

# Tabs migrated to AuthZ, each with one of the permissions that show it.
MIGRATED_TABS = {tab: permissions[0] for tab, permissions in constants.TAB_PERMISSIONS.items()}

# Every (tab, permission) pair: a single permission of the tab is enough to show it.
TAB_PERMISSION_PAIRS = [
    (tab, permission) for tab, permissions in constants.TAB_PERMISSIONS.items() for permission in permissions
]


def allowed_only(*permissions):
    """
    Build an ``is_user_allowed`` side effect that grants only the given permissions.
    """
    return lambda _username, permission, _scope: permission in permissions


@ddt.ddt
class CourseMetadataViewAuthzTest(InstructorAuthzTestMixin, SharedModuleStoreTestCase):
    """
    ``CourseMetadataView`` tabs and permissions follow the AuthZ flag.

    With the flag on they are resolved through AuthZ, and through the legacy
    roles when it is off.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.course = CourseFactory.create()
        cls.course_key = cls.course.id

    def setUp(self):
        super().setUp()
        self.client = APIClient()
        # The Date Extensions tab is only shown when edx-when is enabled for the course.
        patcher = patch("lms.djangoapps.instructor.views.serializers_v2.is_enabled_for_course", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.url = reverse("instructor_api_v2:course_metadata", kwargs={"course_id": str(self.course_key)})

    def _get(self, user):
        self.client.force_authenticate(user=user)
        return self.client.get(self.url)

    def _tab_ids(self, response):
        return {tab["tab_id"] for tab in response.data["tabs"]}

    def test_existing_permissions_field_is_unchanged(self):
        """The legacy ``permissions`` field keeps the same keys."""
        user = self.create_user_with_authz_role(COURSE_ADMIN.external_key, self.course_key)

        response = self._get(user)

        assert response.status_code == status.HTTP_200_OK
        assert set(response.data["permissions"]) == {
            "admin",
            "instructor",
            "finance_admin",
            "sales_admin",
            "staff",
            "forum_admin",
            "data_researcher",
        }

    def test_authz_course_admin_sees_migrated_tabs_and_holds_every_permission(self):
        """A Course Admin sees exactly the migrated tabs and holds every permission."""
        user = self.create_user_with_authz_role(COURSE_ADMIN.external_key, self.course_key)

        response = self._get(user)

        assert response.status_code == status.HTTP_200_OK
        assert self._tab_ids(response) == set(MIGRATED_TABS)
        assert set(response.data["authz_permissions"]) == set(constants.INSTRUCTOR_DASHBOARD_PERMISSIONS)
        assert all(response.data["authz_permissions"].values())

    def test_authz_course_staff_sees_migrated_tabs_but_cannot_manage_course_team(self):
        """A Course Staff sees exactly the migrated tabs but cannot manage the course team."""
        user = self.create_user_with_authz_role(COURSE_STAFF.external_key, self.course_key)

        response = self._get(user)

        assert self._tab_ids(response) == set(MIGRATED_TABS)
        permissions = response.data["authz_permissions"]
        assert permissions[constants.COURSES_VIEW_COURSE_TEAM]
        # Course Staff does not manage the course team.
        assert not permissions[constants.COURSES_MANAGE_COURSE_TEAM]
        assert permissions[constants.COURSES_MANAGE_COHORTS]

    def test_authz_denied_overrides_legacy_roles(self):
        """
        With the flag on, AuthZ denying a legacy instructor means no access.
        """
        instructor = InstructorFactory(course_key=self.course_key)

        with patch(f"{API}.authz_api.is_user_allowed", return_value=False):
            response = self._get(instructor)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @ddt.data(*constants.INSTRUCTOR_DASHBOARD_PERMISSIONS)
    def test_authz_any_dashboard_permission_grants_access(self, permission):
        """With the flag on, a single dashboard permission, not only ``view_course_info``, grants access."""
        user = UserFactory()

        with patch(f"{API}.authz_api.is_user_allowed", side_effect=lambda _u, perm, _s: perm == permission):
            response = self._get(user)

        assert response.status_code == status.HTTP_200_OK

    @ddt.data(*TAB_PERMISSION_PAIRS)
    @ddt.unpack
    def test_authz_tab_shown_with_any_of_its_permissions(self, tab_id, tab_permission):
        """
        A tab is shown with any one of its permissions, and hidden without all of them.
        """
        user = UserFactory()

        with patch(
            f"{API}.authz_api.is_user_allowed", side_effect=allowed_only(constants.COURSES_VIEW_COURSE_INFO)
        ):
            tabs_without_permission = self._tab_ids(self._get(user))
        with patch(
            f"{API}.authz_api.is_user_allowed",
            side_effect=allowed_only(constants.COURSES_VIEW_COURSE_INFO, tab_permission),
        ):
            tabs_with_permission = self._tab_ids(self._get(user))

        assert tab_id in tabs_with_permission
        if tab_id != "course_info":
            assert tab_id not in tabs_without_permission

    def test_legacy_instructor_sees_migrated_tabs(self):
        """With the flag off, a legacy instructor sees every migrated tab and manages the course team."""
        self.set_authz_enabled(False)
        instructor = InstructorFactory(course_key=self.course_key)

        response = self._get(instructor)

        assert response.status_code == status.HTTP_200_OK
        assert "date_extensions" in self._tab_ids(response)
        assert set(MIGRATED_TABS) <= self._tab_ids(response)
        assert response.data["authz_permissions"][constants.COURSES_MANAGE_COURSE_TEAM]

    def test_legacy_staff_has_staff_only_tabs(self):
        """
        Staff without the forum Administrator role does not see Course Team, and
        without instructor access does not see Date Extensions.
        """
        self.set_authz_enabled(False)
        staff = StaffFactory(course_key=self.course_key)

        response = self._get(staff)

        tabs = self._tab_ids(response)
        assert tabs & set(MIGRATED_TABS) == set(MIGRATED_TABS) - {"course_team", "date_extensions"}
        assert not response.data["authz_permissions"][constants.COURSES_MANAGE_COURSE_TEAM]

    def test_legacy_does_not_query_authz(self):
        """With the flag off, AuthZ is not queried."""
        self.set_authz_enabled(False)
        instructor = InstructorFactory(course_key=self.course_key)

        with patch(f"{API}.authz_api.is_user_allowed") as is_user_allowed:
            response = self._get(instructor)

        assert response.status_code == status.HTTP_200_OK
        is_user_allowed.assert_not_called()


@ddt.ddt
class InstructorDashboardTabAuthzTest(InstructorAuthzTestMixin, SharedModuleStoreTestCase):
    """
    The "Instructor" course tab of the LMS follows the AuthZ flag.

    With the flag on it is shown when the user holds at least one of the Instructor
    Dashboard permissions, and through the legacy roles when it is off.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.course = CourseFactory.create()

    def _has_instructor_tab(self, user):
        return any(tab.type == "instructor" for tab in get_course_tab_list(user, self.course))

    def test_authz_role_with_permissions_shown(self):
        """With the flag on, a role that holds dashboard permissions sees the tab."""
        user = self.create_user_with_authz_role(COURSE_STAFF.external_key, self.course.id)

        assert self._has_instructor_tab(user)

    @ddt.data(*constants.INSTRUCTOR_DASHBOARD_PERMISSIONS)
    def test_authz_instructor_course_tab_shown_with_any_dashboard_permission(self, permission):
        """With the flag on, a single dashboard permission is enough to show the "Instructor" course tab."""
        user = UserFactory()

        with patch(f"{API}.authz_api.is_user_allowed", side_effect=lambda _u, perm, _c: perm == permission):
            assert self._has_instructor_tab(user)

    def test_authz_without_permissions_hidden(self):
        """With the flag on, a user holding none of the permissions does not see the tab."""
        user = UserFactory()

        assert not self._has_instructor_tab(user)

    def test_authz_denied_overrides_legacy_staff(self):
        """With the flag on, legacy staff without AuthZ permissions does not see the tab."""
        staff = StaffFactory(course_key=self.course.id)

        with patch(f"{API}.authz_api.is_user_allowed", return_value=False):
            assert not self._has_instructor_tab(staff)

    def test_legacy_staff_shown(self):
        """With the flag off, a legacy staff user sees the tab without querying AuthZ."""
        self.set_authz_enabled(False)
        staff = StaffFactory(course_key=self.course.id)

        with patch(f"{API}.authz_api.is_user_allowed") as is_user_allowed:
            assert self._has_instructor_tab(staff)

        is_user_allowed.assert_not_called()

    def test_legacy_without_role_hidden(self):
        """With the flag off, a user without any role does not see the tab."""
        self.set_authz_enabled(False)

        assert not self._has_instructor_tab(UserFactory())


class CourseTeamAuthzTestMixin(InstructorAuthzTestMixin):
    """
    Setup, helpers and checks shared by the Course Team endpoint tests.

    Each test class defines ``_send_default_request``: a request a course
    instructor is allowed to make on its endpoint.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.course = CourseFactory.create()
        cls.course_key = cls.course.id

    def setUp(self):
        super().setUp()
        self.client = APIClient()

    def _send_default_request(self, user):
        """Send a request a course instructor is allowed to make on the endpoint."""
        raise NotImplementedError

    def _create_user(self, authz_role=None):
        """Create a user with the AuthZ role in the course, or without any role."""
        if authz_role is None:
            return UserFactory()
        return self.create_user_with_authz_role(authz_role, self.course_key)

    def _create_legacy_user(self, legacy_role):
        """
        Create a user with a legacy course role: ``instructor``, ``staff`` or ``forum_admin``.

        ``forum_admin`` is a Discussion Admin: course staff plus the forum
        Administrator role. Call it with the flag off, otherwise the factories
        assign the equivalent AuthZ role instead of the legacy one.
        """
        if legacy_role == "instructor":
            return InstructorFactory(course_key=self.course_key)
        user = StaffFactory(course_key=self.course_key)
        if legacy_role == "forum_admin":
            self._add_forum_role(user, FORUM_ROLE_ADMINISTRATOR)
        return user

    def _add_forum_role(self, user, rolename):
        """Give the user a forum role in the course."""
        seed_permissions_roles(self.course_key)
        Role.objects.get(course_id=self.course_key, name=rolename).users.add(user)

    def _has_course_role(self, role_class, user):
        """Check a course role on a fresh copy of the user, since roles are cached on the user object."""
        return role_class(self.course_key).has_user(get_user_model().objects.get(pk=user.pk))

    def _has_forum_role(self, user, rolename):
        """Check whether the user holds the forum role in the course."""
        return Role.objects.filter(course_id=self.course_key, name=rolename, users=user).exists()

    def test_authz_denied_overrides_legacy_instructor(self):
        """With the flag on, AuthZ denying a legacy instructor means no access."""
        self.set_authz_enabled(False)
        instructor = self._create_legacy_user("instructor")
        self.set_authz_enabled(True)

        with patch(f"{API}.authz_api.is_user_allowed", return_value=False):
            response = self._send_default_request(instructor)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_legacy_does_not_query_authz(self):
        """With the flag off, AuthZ is not queried."""
        self.set_authz_enabled(False)
        instructor = self._create_legacy_user("instructor")

        with patch(f"{API}.authz_api.is_user_allowed") as is_user_allowed:
            response = self._send_default_request(instructor)

        assert response.status_code == status.HTTP_200_OK
        is_user_allowed.assert_not_called()


@ddt.ddt
class CourseTeamRolesViewAuthzTest(CourseTeamAuthzTestMixin, SharedModuleStoreTestCase):
    """
    ``CourseTeamRolesView`` (``GET /team/roles``) follows the AuthZ flag.

    With the flag on, listing the roles requires ``courses.view_course_team``.
    With it off, the legacy ``has_course_team_access`` check is used.
    """

    def setUp(self):
        super().setUp()
        self.url = reverse("instructor_api_v2:course_team_roles", kwargs={"course_id": str(self.course_key)})

    def _get(self, user):
        self.client.force_authenticate(user=user)
        return self.client.get(self.url)

    def _send_default_request(self, user):
        return self._get(user)

    @ddt.data(
        (COURSE_ADMIN.external_key, status.HTTP_200_OK),
        (COURSE_STAFF.external_key, status.HTTP_200_OK),
        (None, status.HTTP_403_FORBIDDEN),
    )
    @ddt.unpack
    def test_authz_list_roles(self, authz_role, expected_status):
        """With the flag on, listing the roles requires ``courses.view_course_team``."""
        user = self._create_user(authz_role)

        response = self._get(user)

        assert response.status_code == expected_status

    @ddt.data(
        ("instructor", status.HTTP_200_OK),
        ("forum_admin", status.HTTP_200_OK),
        ("staff", status.HTTP_403_FORBIDDEN),
    )
    @ddt.unpack
    def test_legacy_list_roles(self, legacy_role, expected_status):
        """With the flag off, instructors and Discussion Admins can list the roles, plain staff cannot."""
        self.set_authz_enabled(False)
        user = self._create_legacy_user(legacy_role)

        response = self._get(user)

        assert response.status_code == expected_status


@ddt.ddt
class CourseTeamViewAuthzTest(CourseTeamAuthzTestMixin, SharedModuleStoreTestCase):
    """
    ``CourseTeamView`` (``GET`` and ``POST /team``) follows the AuthZ flag.

    With the flag on, listing the members requires ``courses.view_course_team``
    and granting or revoking a role requires ``courses.manage_course_team``.
    Changing a non-forum role also requires instructor access, checked by the
    view. With the flag off, both methods use the legacy
    ``has_course_team_access`` check.
    """

    def setUp(self):
        super().setUp()
        self.url = reverse("instructor_api_v2:course_team", kwargs={"course_id": str(self.course_key)})
        self.target = UserFactory()

    def _get(self, user):
        self.client.force_authenticate(user=user)
        return self.client.get(self.url)

    def _grant(self, user, role, identifier=None):
        """Grant the role to the target user, or to ``identifier`` if given."""
        self.client.force_authenticate(user=user)
        data = {"identifiers": [identifier or self.target.username], "role": role, "action": "allow"}
        return self.client.post(self.url, data, format="json")

    def _send_default_request(self, user):
        return self._get(user)

    @ddt.data(
        (COURSE_ADMIN.external_key, status.HTTP_200_OK),
        (COURSE_STAFF.external_key, status.HTTP_200_OK),
        (None, status.HTTP_403_FORBIDDEN),
    )
    @ddt.unpack
    def test_authz_list_members(self, authz_role, expected_status):
        """With the flag on, listing the members requires ``courses.view_course_team``."""
        user = self._create_user(authz_role)

        response = self._get(user)

        assert response.status_code == expected_status

    @ddt.data(
        (COURSE_ADMIN.external_key, status.HTTP_200_OK),
        (COURSE_STAFF.external_key, status.HTTP_403_FORBIDDEN),
        (None, status.HTTP_403_FORBIDDEN),
    )
    @ddt.unpack
    def test_authz_grant_role(self, authz_role, expected_status):
        """With the flag on, granting a role requires ``courses.manage_course_team``."""
        user = self._create_user(authz_role)

        response = self._grant(user, "staff")

        assert response.status_code == expected_status
        assert self._has_course_role(CourseStaffRole, self.target) == (expected_status == status.HTTP_200_OK)

    def test_authz_course_admin_can_grant_instructor_role(self):
        """With the flag on, a Course Admin without any legacy role can grant the instructor role."""
        admin = self._create_user(COURSE_ADMIN.external_key)

        response = self._grant(admin, "instructor")

        assert response.status_code == status.HTTP_200_OK
        assert self._has_course_role(CourseInstructorRole, self.target)

    def test_authz_course_staff_cannot_grant_itself_instructor_role(self):
        """
        Privilege escalation: a Course Staff, which can only view the course
        team, cannot make itself a course instructor.
        """
        staff = self._create_user(COURSE_STAFF.external_key)

        response = self._grant(staff, "instructor", identifier=staff.username)

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert not self._has_course_role(CourseInstructorRole, staff)

    @ddt.data(
        ("instructor", CourseInstructorRole),
        ("staff", CourseStaffRole),
    )
    @ddt.unpack
    def test_authz_manage_course_team_without_instructor_access_cannot_grant_course_role(self, role, role_class):
        """
        Privilege escalation: ``courses.manage_course_team`` without instructor
        access cannot grant a non-forum role.
        """
        user = self._create_user()

        with patch(f"{API}.authz_api.is_user_allowed", side_effect=allowed_only(constants.COURSES_MANAGE_COURSE_TEAM)):
            response = self._grant(user, role)

        assert response.status_code == status.HTTP_403_FORBIDDEN
        # Denied by the view's own check, not by the permission class (which answers with ``developer_message``).
        assert "error" in response.data
        assert not self._has_course_role(role_class, self.target)

    def test_authz_manage_course_team_without_instructor_access_can_grant_forum_role(self):
        """``courses.manage_course_team`` without instructor access can still grant forum roles."""
        seed_permissions_roles(self.course_key)
        user = self._create_user()

        with patch(f"{API}.authz_api.is_user_allowed", side_effect=allowed_only(constants.COURSES_MANAGE_COURSE_TEAM)):
            response = self._grant(user, FORUM_ROLE_MODERATOR)

        assert response.status_code == status.HTTP_200_OK
        assert self._has_forum_role(self.target, FORUM_ROLE_MODERATOR)

    @ddt.data(
        ("instructor", status.HTTP_200_OK),
        ("forum_admin", status.HTTP_200_OK),
        ("staff", status.HTTP_403_FORBIDDEN),
    )
    @ddt.unpack
    def test_legacy_list_members(self, legacy_role, expected_status):
        """With the flag off, instructors and Discussion Admins can list the members, plain staff cannot."""
        self.set_authz_enabled(False)
        user = self._create_legacy_user(legacy_role)

        response = self._get(user)

        assert response.status_code == expected_status

    def test_legacy_instructor_can_grant_role(self):
        """With the flag off, a legacy instructor can grant a role."""
        self.set_authz_enabled(False)
        instructor = self._create_legacy_user("instructor")

        response = self._grant(instructor, "staff")

        assert response.status_code == status.HTTP_200_OK
        assert self._has_course_role(CourseStaffRole, self.target)


@ddt.ddt
class CourseTeamMemberViewAuthzTest(CourseTeamAuthzTestMixin, SharedModuleStoreTestCase):
    """
    ``CourseTeamMemberView`` (``DELETE /team/<email_or_username>``) follows the AuthZ flag.

    With the flag on, revoking a role requires ``courses.manage_course_team``.
    Revoking a non-forum role also requires instructor access, checked by the
    view. With the flag off, the legacy ``has_course_team_access`` check is used.
    """

    def _revoke(self, user, target, roles):
        """Revoke the roles from the target user, acting as ``user``."""
        self.client.force_authenticate(user=user)
        url = reverse(
            "instructor_api_v2:course_team_member",
            kwargs={"course_id": str(self.course_key), "email_or_username": target.username},
        )
        return self.client.delete(url, {"roles": roles}, format="json")

    def _send_default_request(self, user):
        return self._revoke(user, StaffFactory(course_key=self.course_key), ["staff"])

    @ddt.data(
        (COURSE_ADMIN.external_key, status.HTTP_200_OK),
        (COURSE_STAFF.external_key, status.HTTP_403_FORBIDDEN),
        (None, status.HTTP_403_FORBIDDEN),
    )
    @ddt.unpack
    def test_authz_revoke_role(self, authz_role, expected_status):
        """With the flag on, revoking a role requires ``courses.manage_course_team``."""
        target = StaffFactory(course_key=self.course_key)
        user = self._create_user(authz_role)

        response = self._revoke(user, target, ["staff"])

        assert response.status_code == expected_status
        assert self._has_course_role(CourseStaffRole, target) == (expected_status != status.HTTP_200_OK)

    def test_authz_course_staff_cannot_revoke_course_admin(self):
        """Privilege escalation: a Course Staff cannot remove a course instructor."""
        admin = self._create_user(COURSE_ADMIN.external_key)
        staff = self._create_user(COURSE_STAFF.external_key)

        response = self._revoke(staff, admin, ["instructor"])

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert self._has_course_role(CourseInstructorRole, admin)

    @ddt.data(
        ("instructor", CourseInstructorRole, InstructorFactory),
        ("staff", CourseStaffRole, StaffFactory),
    )
    @ddt.unpack
    def test_authz_manage_course_team_without_instructor_access_cannot_revoke_course_role(
        self, role, role_class, target_factory
    ):
        """
        Privilege escalation: ``courses.manage_course_team`` without instructor
        access cannot revoke a non-forum role.
        """
        target = target_factory(course_key=self.course_key)
        user = self._create_user()

        with patch(f"{API}.authz_api.is_user_allowed", side_effect=allowed_only(constants.COURSES_MANAGE_COURSE_TEAM)):
            response = self._revoke(user, target, [role])

        assert response.status_code == status.HTTP_403_FORBIDDEN
        # Denied by the view's own check, not by the permission class (which answers with ``developer_message``).
        assert "error" in response.data
        assert self._has_course_role(role_class, target)

    def test_authz_manage_course_team_without_instructor_access_can_revoke_forum_role(self):
        """``courses.manage_course_team`` without instructor access can still revoke forum roles."""
        target = self._create_user()
        self._add_forum_role(target, FORUM_ROLE_MODERATOR)
        user = self._create_user()

        with patch(f"{API}.authz_api.is_user_allowed", side_effect=allowed_only(constants.COURSES_MANAGE_COURSE_TEAM)):
            response = self._revoke(user, target, [FORUM_ROLE_MODERATOR])

        assert response.status_code == status.HTTP_200_OK
        assert not self._has_forum_role(target, FORUM_ROLE_MODERATOR)

    @ddt.data(
        ("instructor", status.HTTP_200_OK),
        ("forum_admin", status.HTTP_403_FORBIDDEN),
        ("staff", status.HTTP_403_FORBIDDEN),
    )
    @ddt.unpack
    def test_legacy_revoke_staff_role(self, legacy_role, expected_status):
        """
        With the flag off, only legacy instructors can revoke the staff role. A
        Discussion Admin passes the permission class but is denied by the view.
        """
        self.set_authz_enabled(False)
        target = StaffFactory(course_key=self.course_key)
        user = self._create_legacy_user(legacy_role)

        response = self._revoke(user, target, ["staff"])

        assert response.status_code == expected_status
        assert self._has_course_role(CourseStaffRole, target) == (expected_status != status.HTTP_200_OK)

    def test_legacy_forum_admin_can_revoke_forum_role(self):
        """With the flag off, a Discussion Admin can revoke a forum role."""
        self.set_authz_enabled(False)
        forum_admin = self._create_legacy_user("forum_admin")
        target = self._create_user()
        self._add_forum_role(target, FORUM_ROLE_MODERATOR)

        response = self._revoke(forum_admin, target, [FORUM_ROLE_MODERATOR])

        assert response.status_code == status.HTTP_200_OK
        assert not self._has_forum_role(target, FORUM_ROLE_MODERATOR)

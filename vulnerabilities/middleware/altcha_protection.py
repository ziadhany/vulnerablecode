#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import time

from django.shortcuts import redirect
from django.utils.deprecation import MiddlewareMixin


class AltchaProtectionMiddleware(MiddlewareMixin):
    PROTECTED_PREFIXES = (
        "/packages/",
        "/vulnerabilities/",
        "/advisories/",
        "/affected-by-advisories/v2/",
        "/fixing-advisories/v2/",
    )

    SESSION_TIMEOUT = 3600  # 1 hour

    def __call__(self, request):
        protected = any(request.path.startswith(prefix) for prefix in self.PROTECTED_PREFIXES)

        if not protected:
            return self.get_response(request)

        verified_at = request.session.get("altcha_verified_at")

        if not verified_at:
            return redirect(f"/altcha/")

        if time.time() - verified_at > self.SESSION_TIMEOUT:
            request.session.pop("altcha_verified_at", None)
            return redirect(f"/altcha/")

        return self.get_response(request)

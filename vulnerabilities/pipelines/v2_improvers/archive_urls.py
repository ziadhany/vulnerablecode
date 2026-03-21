#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import time
import requests
from vulnerabilities.models import AdvisoryReference
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.wayback_machine import WaybackMachineSaveAPI


class ArchiveImproverPipeline(VulnerableCodePipeline):
    """
    Archive Improver Pipeline
    """

    pipeline_id = "archive_improver_pipeline"

    @classmethod
    def steps(cls):
        return (cls.archive_urls,)

    def archive_urls(self):
        advisory_refs = AdvisoryReference.objects.filter(archive_url__isnull=True).only("id", "url")

        for advisory_ref in advisory_refs.iterator():

            if not advisory_ref.url.startswith("http"):
                continue

            if not self.is_reachable_url(advisory_ref.url):
                self.log(
                    f"Skipping archival: URL is unreachable or returned 404: {advisory_ref.url}"
                )
                continue

            self.log(f"Requesting archival for: {advisory_ref.url}")
            try:
                time.sleep(300)
                archive_url = self.request_archival(advisory_ref.url)
                if not archive_url:
                    continue

                AdvisoryReference.objects.filter(id=advisory_ref.id).update(archive_url=archive_url)
                self.log(f"Successfully added archival URL for advisory reference: {archive_url}")
            except Exception as e:
                self.log(f"Failed to archive {advisory_ref.url}: {str(e)}")

    def request_archival(self, url):
        user_agent = "Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0"
        try:
            save_api = WaybackMachineSaveAPI(url, user_agent)
            return save_api.save()
        except Exception as e:
            self.log(f"Failed to archive {url}: {str(e)}")
            return None

    def is_reachable_url(self, url):
        try:
            with requests.Session() as session:
                head_res = session.head(url, allow_redirects=True, timeout=10)
                if not head_res.status_code == 200:
                    return False

                get_res = session.get(url, allow_redirects=True, stream=True, timeout=10)
                return get_res.status_code == 200

        except requests.RequestException:
            return False

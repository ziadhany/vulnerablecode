#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import re
import shutil
from pathlib import Path

from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import cve_regex
from vulnerabilities.utils import get_advisory_url


class LinuxKernelPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Pipeline to collect Linux Kernel Pipeline:
    """

    pipeline_id = "linux_kernel_cves_fix_commits"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/nluedtke/linux_kernel_cves/blob/master/LICENSE"
    importer_name = "linux_kernel_cves_fix_commits"
    qualified_name = "linux_kernel_cves_fix_commits"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def advisories_count(self):
        root = Path(self.vcs_response.dest_dir)
        return sum(1 for _ in root.rglob("data/*.txt"))

    def clone(self):
        self.repo_url = "git+https://github.com/nluedtke/linux_kernel_cves"
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def collect_advisories(self):
        self.log(f"Processing linux kernel fix commits.")
        base_path = Path(self.vcs_response.dest_dir) / "data"
        for file_path in base_path.rglob("*.txt"):
            if "_CVEs.txt" in file_path.name:
                continue

            if "_security.txt" in file_path.name:
                for vulnerability_id, commit_hash in self.parse_commits_file(file_path):

                    kernel_urls = [
                        f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/{commit_hash}",
                        f"https://github.com/torvalds/linux/commit/{commit_hash}",
                    ]

                    if not (vulnerability_id and commit_hash):
                        continue

                    references = []
                    for kernel_url in kernel_urls:
                        ref = ReferenceV2(
                            reference_type="commit",
                            url=kernel_url,
                        )
                        references.append(ref)

                    advisory_url = get_advisory_url(
                        file=file_path,
                        base_path=self.vcs_response.dest_dir,
                        url="https://github.com/nluedtke/linux_kernel_cves/blob/master/",
                    )

                    yield AdvisoryData(
                        advisory_id=vulnerability_id,
                        references_v2=references,
                        url=advisory_url,
                    )

    def parse_commits_file(self, file_path):
        sha1_pattern = re.compile(r"\b[a-f0-9]{40}\b")

        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                cve_match = cve_regex.search(line)
                if not cve_match:
                    continue

                cve = cve_match.group(0)

                sha1_match = sha1_pattern.search(line)
                commit_hash = sha1_match.group(0) if sha1_match else None
                yield cve, commit_hash

    def clean_downloads(self):
        """Cleanup any temporary repository data."""
        self.log("Cleaning up local repository resources.")
        if hasattr(self, "repo") and self.repo.working_dir:
            shutil.rmtree(path=self.repo.working_dir)

    def on_failure(self):
        """Ensure cleanup is always performed on failure."""
        self.clean_downloads()

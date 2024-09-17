import logging

import requests
import saneyaml
from aboutcode.pipeline import LoopProgress
from dateutil import parser as dateparser

from vulnerabilities.models import Alias
from vulnerabilities.models import Exploit
from vulnerabilities.pipelines import VulnerableCodePipeline

module_logger = logging.getLogger(__name__)


class MetasploitImproverPipeline(VulnerableCodePipeline):
    """
    Metasploit Exploits Pipeline: Retrieve Metasploit data, iterate through it to identify vulnerabilities
    by their associated aliases, and create or update the corresponding Exploit instances.
    """

    license_expression = "BSD-3-clause"

    @classmethod
    def steps(cls):
        return (
            cls.fetch_exploits,
            cls.add_vulnerability_exploits,
        )

    def fetch_exploits(self):
        url = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
        self.log(f"Fetching {url}")
        try:
            response = requests.get(url)
            response.raise_for_status()
        except requests.exceptions.HTTPError as http_err:
            self.log(
                f"Failed to fetch the Metasploit Exploits: {url} - {http_err}", level=logging.ERROR
            )
            raise

        self.metasploit_data = response.json()

    def add_vulnerability_exploits(self):
        fetched_exploit_count = len(self.metasploit_data)
        self.log(f"Enhancing the vulnerability with {fetched_exploit_count:,d} exploit records")

        vulnerability_exploit_count = 0
        progress = LoopProgress(total_iterations=fetched_exploit_count, logger=self.log)
        for _, record in progress.iter(self.metasploit_data.items()):
            vulnerability_exploit_count += add_vulnerability_exploit(
                record=record,
                logger=self.log,
            )
        self.log(f"Successfully added {vulnerability_exploit_count:,d} vulnerability exploit")


def add_vulnerability_exploit(record, logger):
    vulnerability = None
    references = record.get("references", [])
    for ref in references:
        if ref.startswith("OSVDB") or ref.startswith("URL-"):
            # ignore OSV-DB and reference exploit for metasploit
            continue

        try:
            if alias := Alias.objects.get(alias=ref):
                vulnerability = alias.vulnerability
                break
        except Alias.DoesNotExist:
            continue

    if not vulnerability:
        logger(f"No vulnerability found for aliases {references}")
        return 0

    description = record.get("description", "")
    notes = record.get("notes", {})
    platform = record.get("platform")

    source_url = ""
    if path := record.get("path"):
        source_url = f"https://github.com/rapid7/metasploit-framework/tree/master{path}"
    source_date_published = None

    if disclosure_date := record.get("disclosure_date"):
        try:
            source_date_published = dateparser.parse(disclosure_date).date()
        except ValueError:
            logger(f"Error while parsing date {disclosure_date}", level=logging.ERROR)

    Exploit.objects.update_or_create(
        vulnerability=vulnerability,
        data_source="Metasploit",
        defaults={
            "description": description,
            "notes": saneyaml.dump(notes),
            "source_date_published": source_date_published,
            "platform": platform,
            "source_url": source_url,
        },
    )
    return 1
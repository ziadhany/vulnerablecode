import json
from pathlib import Path

from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import DetectionRule
from vulnerabilities.models import DetectionRuleTypes
from vulnerabilities.pipelines import VulnerableCodePipeline


class DetectionRulesPipeline(VulnerableCodePipeline):
    """
    Pipeline to collect vulnerability scanner rules (Sigma, YARA, Suricata, ClamAV entries)
    """

    pipeline_id = "detection_rules"
    license_url = "https://github.com/aboutcode-data/detection-rules-collector/blob/master/LICENSE"
    precedence = 200

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_detection_rules,
            cls.clean_downloads,
        )

    def clone(self):
        self.repo_url = "git+https://github.com/aboutcode-data/detection-rules-collector"
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def advisories_count(self):
        return 0

    def collect_detection_rules(self):
        base_path = Path(self.vcs_response.dest_dir) / "data"
        rule_type_mapping = {
            DetectionRuleTypes.YARA: "yara/**/*.json",
            DetectionRuleTypes.SURICATA: "suricata/**/*.json",
            DetectionRuleTypes.SIGMA: "sigma/**/*.json",
            DetectionRuleTypes.CLAMAV: "clamav/**/*.json",
        }

        for rule_type, glob_pattern in rule_type_mapping.items():
            for file_path in base_path.glob(glob_pattern):
                with open(file_path, "r") as f:
                    try:
                        json_data = json.load(f)
                    except json.JSONDecodeError:
                        self.log(f"Failed to parse JSON in {file_path}")
                        continue

                source_url = json_data.get("source_url")
                for rule in json_data.get("rules", []):
                    vulns_id = rule.get("vulnerabilities", [])
                    advisories = get_related_advisories(vulns_id)

                    raw_text = rule.get("rule_text")
                    rule_metadata = rule.get("rule_metadata")
                    detection_rule, _ = DetectionRule.objects.get_or_create(
                        rule_text=raw_text,
                        defaults={
                            "source_url": source_url,
                            "rule_type": rule_type,
                            "rule_metadata": rule_metadata,
                        },
                    )
                    if advisories:
                        detection_rule.related_advisories.add(*advisories)

    def clean_downloads(self):
        """Cleanup any temporary repository data."""
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        """Ensure cleanup is always performed on failure."""
        self.clean_downloads()


def get_related_advisories(vulnerability_ids, logger=print):
    """
    Fetches related advisories for a list of vulnerability IDs.
    """
    advisories = set()

    for vulnerability_id in vulnerability_ids:
        try:
            alias = AdvisoryAlias.objects.get(alias=vulnerability_id)
            advs = alias.advisories.all()
            advisories.update(advs)

        except AdvisoryAlias.DoesNotExist:
            advs = AdvisoryV2.objects.filter(advisory_id=vulnerability_id).latest_per_avid()

            if advs:
                advisories.update(advs)
            else:
                logger(f"No advisory found for ID/alias: {vulnerability_id}")

    return advisories

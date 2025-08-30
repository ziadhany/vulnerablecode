import json
import os
import re

from black.trans import defaultdict
from git import Repo


def clone_repo(repo_url: str, clone_dir: str) -> str:
    # Ensure the target directory exists
    os.makedirs(clone_dir, exist_ok=True)

    try:
        print(f"Cloning {repo_url} into {clone_dir}...")
        repo = Repo.clone_from(repo_url, clone_dir)
        print("Clone successful.")
        return repo.working_tree_dir
    except Exception as e:
        print(f"Failed to clone repository: {e}")
        return ""


def classify_commit_type(commit):
    """
    Classify commit into root, normal, or merge based on parent count.
    """
    num_parents = len(commit.parents)

    if num_parents == 0:
        return "root"  # never a fix
    elif num_parents == 1:
        return "normal"  # main source of fixes
    else:
        return "merge"  # usually not a fix


def detect_fix_commit(commit):
    """
    Detect whether a commit is a bug-fix or vulnerability-fix commit.
    Returns: "vulnerability_fix", "code_fix", "other"
    """
    msg = commit.message.lower()

    # Vulnerability/security fix patterns
    security_patterns = ["cve-[0-9]{4}-[0-9]{4,19}"]

    if any(re.search(p, msg) for p in security_patterns):
        return "vulnerability_fix"

    return "other"


def extract_cves(text: str) -> list[str]:
    if not text:
        return []

    cves = re.findall("cve-[0-9]{4}-[0-9]{4,19}", text, flags=re.IGNORECASE)

    # Normalize format (uppercase) and remove duplicates
    return list(set(cve.upper() for cve in cves))


def classify_diff(commit) -> bool:
    """
    Return True  -> commit touches at least one non-doc file (i.e., code change)
    Return False -> commit touches ONLY doc/text files
    """
    doc_extensions = {
        ".txt",
        ".md",
        ".rst",
        ".mdx",
        ".doc",
        ".docx",
        ".odt",
        ".rtf",
        ".pdf",
        ".adoc",
        ".asciidoc",
        ".tex",
        ".markdown",
    }

    # FIXME
    return True


if __name__ == "__main__":
    repo_url = "https://github.com/openssl/openssl/"
    repo_path = clone_repo(repo_url, clone_dir=f"/tmp/{hash(repo_url)}")

    repo = Repo(repo_path)
    commits_data = []
    cve_list = defaultdict(set)

    for commit in repo.iter_commits("--all"):
        """
        - Root commits ( Never a fix ) Can be ignored in fix detection.
        - Normal commits main source of bug/security fixes.
        - Merge commits ( A merge commit itself is usually not the fix ,it just joins two histories. )
        """
        commit_type = classify_commit_type(commit)
        is_fix_commit = detect_fix_commit(commit)

        if is_fix_commit in "vulnerability_fix" and commit_type in ["normal", "merge"]:
            is_not_docs = classify_diff(commit)
            if is_not_docs:
                commits_data.append(
                    {
                        "hash": commit.hexsha,
                        "author": commit.author.name,
                        "email": commit.author.email,
                        "date": commit.committed_datetime.isoformat(),
                        "message": commit.message.strip(),
                    }
                )

            cves_temp = extract_cves(commit.message.strip())
            for cve_temp in cves_temp:
                cve_list[cve_temp].add("https://github.com/openssl/openssl/commit/" + commit.hexsha)

    # Convert sets to lists for JSON serialization
    result = {cve: list(commits) for cve, commits in cve_list.items()}

    print(f"Found {len(result)} unique CVEs")
    print(json.dumps(result, indent=2))

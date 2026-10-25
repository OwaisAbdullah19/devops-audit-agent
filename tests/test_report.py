import json

from report import normalize_violations, validate_report, write_report


def v(**kw):
    base = {"category": "security", "severity": "high", "file": "config.py", "line": 3,
            "description": "Hardcoded API credential", "evidence": "Literal assigned", "recommendation": "Use env var"}
    base.update(kw)
    return base


def test_valid_and_rule_ids(repo):
    out, rej = normalize_violations([v(), v(category="ci", file=".github/workflows/ci.yml", line=0,
                                          description="Other thing", severity="medium")], repo)
    assert not rej and [x["rule_id"] for x in out] == ["SEC-001", "CI-001"]
    assert out[1]["category"] == "ci_cd" and out[1]["line"] is None


def test_rejects_hallucinated_file_bad_line_bad_severity(repo):
    out, rej = normalize_violations([v(file="ghost.py"), v(line=999), v(severity="urgent"), v(category="magic")], repo)
    assert out == [] and len(rej) == 4


def test_missing_file_finding_uses_null(repo):
    out, _ = normalize_violations([v(category="testing", file="", line=0, description="No tests directory")], repo)
    assert out[0]["file"] is None and out[0]["line"] is None


def test_dedup(repo):
    out, _ = normalize_violations([v(), v(description="Hardcoded API credential found"), v(line=4, description="Hardcoded password")], repo)
    assert len(out) == 2


def test_secrets_never_in_report(repo):
    out, _ = normalize_violations([v(evidence='API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"')], repo)
    assert "sk-abcdef" not in json.dumps(out)


def test_write_and_validate(repo, tmp_path):
    out, _ = normalize_violations([v()], repo)
    p = tmp_path / "sub" / "r.json"
    write_report(p, "https://github.com/o/r", out)
    data = json.loads(p.read_text())
    assert validate_report(data) == [] and set(data) == {"repository", "violations"}
    write_report(p, "https://github.com/o/r", [])
    assert json.loads(p.read_text())["violations"] == []


def test_validate_flags_bad_reports():
    assert validate_report({"repository": "x"})
    assert validate_report({"repository": "x", "violations": [{"rule_id": "A"}]})


def test_same_location_hygiene_and_security_are_merged_keeping_the_more_severe(repo):
    a = v(category="repository_hygiene", severity="medium", file="config.py", line=3, description="Env-like file tracked in git")
    b = v(category="security", severity="high", file="config.py", line=3, description="Credentials committed")
    out, _ = normalize_violations([a, b], repo)
    assert len(out) == 1 and out[0]["category"] == "security" and out[0]["severity"] == "high"
    out, _ = normalize_violations([b, a], repo)
    assert len(out) == 1 and out[0]["severity"] == "high"
    # different lines are different defects
    c = v(category="repository_hygiene", severity="low", file="config.py", line=5, description="Other thing tracked")
    assert len(normalize_violations([b, c], repo)[0]) == 2


def test_off_by_one_line_is_snapped_to_the_line_with_the_identifier(repo):
    # fixture config.py: line 3 holds API_KEY, line 4 holds the password assignment
    out, rej = normalize_violations([v(line=4, description="API_KEY is hardcoded", evidence="API_KEY assigned a literal value")], repo)
    assert not rej and out[0]["line"] == 3


def test_correct_or_unrelated_lines_are_left_alone(repo):
    ok, _ = normalize_violations([v(line=3, description="API_KEY is hardcoded", evidence="API_KEY literal")], repo)
    assert ok[0]["line"] == 3
    far, _ = normalize_violations([v(line=5, description="MISSING_SETTING is hardcoded elsewhere", evidence="MISSING_SETTING hardcoded")], repo)
    assert far[0]["line"] == 5            # identifier not nearby -> unchanged
    plain, _ = normalize_violations([v(line=4, description="Something wrong here", evidence="no identifiers at all")], repo)
    assert plain[0]["line"] == 4


def test_snap_prefers_line_with_the_more_specific_expression(tmp_path):
    root = tmp_path / "w"
    (root / ".github").mkdir(parents=True)
    (root / ".github/pr.yml").write_text(
        "steps:\n  - uses: actions/checkout@v4\n    with:\n      ref: ${{ github.event.pull_request.head.sha }}\n"
        "  - name: Log\n    run: echo \"${{ github.event.pull_request.title }}\"\n")
    f = v(file=".github/pr.yml", line=4, category="security",
          description="Script injection via untrusted event expression",
          evidence="github.event.pull_request.title is interpolated into a shell run step")
    out, rej = normalize_violations([f], root)
    assert not rej and out[0]["line"] == 6


def test_snap_does_not_move_bundled_finding_to_the_other_identifier(repo):
    # line 3 has API_KEY, line 2 has DB_URL; a finding naming both and citing line 3 must stay on line 3
    out, _ = normalize_violations([v(line=3, description="API_KEY and DB_URL are hardcoded", evidence="API_KEY and DB_URL literal")], repo)
    assert out[0]["line"] == 3


def _dockerfile_repo(tmp_path):
    d = tmp_path / "df"
    d.mkdir()
    (d / "Dockerfile").write_text("FROM python:latest\nWORKDIR /app\nCOPY . .\nRUN pip install flask\nCMD [\"python\"]\n")
    return d


def test_two_different_defects_on_the_same_line_are_both_kept(tmp_path):
    d = _dockerfile_repo(tmp_path)
    latest = {"category": "build_release", "severity": "medium", "file": "Dockerfile", "line": 1,
              "description": "Dockerfile uses mutable latest base image tag.",
              "evidence": "Dockerfile starts with FROM python:latest.", "recommendation": "Pin it."}
    root = {"category": "build_release", "severity": "medium", "file": "Dockerfile", "line": 1,
            "description": "Dockerfile runs container as the root user.",
            "evidence": "Dockerfile lacks a USER instruction, defaulting to root.", "recommendation": "Add USER."}
    out, _ = normalize_violations([latest, root], d)
    assert len(out) == 2


def test_same_defect_described_twice_is_still_merged(tmp_path):
    d = _dockerfile_repo(tmp_path)
    a = {"category": "build_release", "severity": "medium", "file": "Dockerfile", "line": 1,
         "description": "Dockerfile uses the floating latest tag for the base image.",
         "evidence": "FROM python:latest in Dockerfile uses latest tag.", "recommendation": "Pin the base image."}
    b = {"category": "build_release", "severity": "low", "file": "Dockerfile", "line": 1,
         "description": "Base image uses latest tag in Dockerfile.",
         "evidence": "Dockerfile FROM python:latest uses the latest tag.", "recommendation": "Use a pinned tag."}
    out, _ = normalize_violations([a, b], d)
    assert len(out) == 1


def test_env_reported_as_hygiene_and_security_is_merged_with_real_wording(tmp_path):
    d = tmp_path / "e"
    d.mkdir()
    (d / ".env").write_text("SECRET_KEY=abc\n")
    sec = {"category": "security", "severity": "high", "file": ".env", "line": 1,
           "description": "Sensitive credentials are hardcoded in a committed .env file.",
           "evidence": ".env contains literal secret key-value assignments and is tracked in git.", "recommendation": "Remove it."}
    hyg = {"category": "repository_hygiene", "severity": "medium", "file": ".env", "line": 1,
           "description": "Temporary or sensitive environment file .env is tracked in version control.",
           "evidence": ".env is tracked in git and flagged by secret scanning.", "recommendation": "Ignore it."}
    out, _ = normalize_violations([sec, hyg], d)
    assert len(out) == 1 and out[0]["category"] == "security"

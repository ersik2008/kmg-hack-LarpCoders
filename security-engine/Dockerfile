FROM python:3.11-slim

# Install system dependencies and scanners
RUN apt-get update && apt-get install -y curl wget git unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep into its own isolated virtualenv via pipx.
#
# IMPORTANT: semgrep must NOT share a site-packages with the FastAPI service.
# Installing both into the system interpreter let requirements.txt (pydantic==2.5.2)
# downgrade semgrep's pydantic, and semgrep then crashed on every single
# invocation with "No module named 'pydantic._internal._signature'" — i.e. SAST
# silently never ran. pipx keeps the two dependency trees apart.
ENV PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/usr/local/bin
RUN python3 -m pip install --no-cache-dir pipx \
    && pipx install semgrep \
    && semgrep --version

# Install Gitleaks
RUN wget https://github.com/zricethezav/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz \
    && tar -xzf gitleaks_8.18.1_linux_x64.tar.gz \
    && mv gitleaks /usr/local/bin/ \
    && rm gitleaks_8.18.1_linux_x64.tar.gz

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Pre-seed the Trivy vulnerability DB so the first scan does not pay for the
# download (and so scans still work if the DB mirror is briefly unreachable).
RUN trivy --cache-dir /root/.cache/trivy image --download-db-only || true

# Bundle the official open-source Semgrep security rules into the image.
#
# A scan must never depend on the Semgrep registry being reachable — a network
# blip would silently reduce SAST coverage to nothing — so the rules ship with
# the image. Only the per-language `security` rule sets are kept; test fixtures
# and the Apex rules (which require a proprietary Semgrep plugin and emit
# "Missing plugin" noise on every scan) are dropped.
ARG SEMGREP_RULES_REF=develop
# Only keep rulesets for languages the platform actually scans.
# The full clone has 1310+ YAML files (Scala, Rust, Go, Java, …) that Semgrep
# must parse and match on every scan, blowing the 300 s timeout even for small
# repos. Keeping just the languages below cuts the rule count to ~550 while
# preserving full coverage for PHP / JS / TS / Python projects.
ARG SEMGREP_KEEP_LANGS="javascript typescript php python bash generic html yaml json dockerfile"
RUN git clone --depth 1 --branch "$SEMGREP_RULES_REF" \
        https://github.com/semgrep/semgrep-rules /tmp/semgrep-rules \
    && mkdir -p /opt/semgrep-rules \
    && cd /tmp/semgrep-rules \
    && for lang in $SEMGREP_KEEP_LANGS; do \
         find "./$lang" -type d -name security -not -path '*/tests/*' \
              -exec cp -r --parents {} /opt/semgrep-rules/ ';' 2>/dev/null || true; \
       done \
    && find /opt/semgrep-rules -name '*.test.yaml' -delete \
    && rm -rf /tmp/semgrep-rules \
    && echo "bundled $(find /opt/semgrep-rules -name '*.yaml' | wc -l) semgrep rule files"

# Semgrep: never phone home, never block on the version check.
# SEMGREP_RULES_DIRS lists the local rule sets used on every scan.
ENV SEMGREP_SEND_METRICS=off \
    SEMGREP_RULES_DIRS=/app/rules,/opt/semgrep-rules \
    SEMGREP_TIMEOUT_SECONDS=600 \
    TRIVY_CACHE_DIR=/root/.cache/trivy \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Fail the build (instead of every scan at runtime) if semgrep is broken or a
# bundled ruleset does not compile.
RUN semgrep scan --validate --config /app/rules --config /opt/semgrep-rules --metrics off

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

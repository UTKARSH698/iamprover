#!/usr/bin/env bash
# Reproduce docs/VALIDATION.md: plan Bishop Fox's IAM Vulnerable lab offline
# (no AWS account or credentials needed) and score iamprover against it.
#
#   bash scripts/iam-vulnerable/run.sh            # needs git, terraform, python
#
# Nothing is applied: `terraform plan` runs with dummy credentials and
# -refresh=false, and the lab's only AWS-calling data sources are replaced
# with literals (see main.tf).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="${WORK_DIR:-$here/.work}"
rm -rf "$work" && mkdir -p "$work"

git clone -q --depth 1 https://github.com/BishopFox/iam-vulnerable.git "$work/lab"
echo "lab commit: $(git -C "$work/lab" rev-parse --short HEAD)"

mkdir -p "$work/plan"
cp -r "$work/lab/modules" "$work/lab/variables.tf" "$work/plan/"
cp "$here/main.tf" "$work/plan/main.tf"
# The one data source that calls AWS: use the managed policy's well-known ARN.
python - "$work/plan/modules/free-resources/privesc-paths/service-linked-role-common.tf" <<'EOF'
import re, sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
s = re.sub(r'data "aws_iam_policy" "AmazonSSMManagedInstanceCore" \{[^}]*\}', "", s)
s = s.replace("data.aws_iam_policy.AmazonSSMManagedInstanceCore.arn",
              '"arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"')
p.write_text(s)
EOF

cd "$work/plan"
terraform init -input=false -no-color >/dev/null
terraform plan -input=false -no-color -refresh=false -out plan.bin >/dev/null
terraform show -json plan.bin > plan.json

for closure in none all; do
  iamprover verify --tf-plan plan.json --tf-account-id 111122223333 \
    --privesc --closure "$closure" --format json > "results-$closure.json" \
    || [ $? -eq 2 ]  # 2 = violations found (expected); anything else is a real failure
done
python "$here/score.py" plan.json results-none.json results-all.json

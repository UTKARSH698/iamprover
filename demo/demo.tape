# VHS tape for the README demo GIF — https://github.com/charmbracelet/vhs
#
# Rendered automatically by .github/workflows/demo.yml on every change to this
# file (vhs does not run natively on Windows — CI is the supported path here).
# Local render on Linux/macOS:   vhs demo/demo.tape   (needs vhs, ffmpeg, ttyd)

Output demo/demo.gif

Set FontSize 15
Set Width 1100
Set Height 620
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Padding 12

Type "# Prove security invariants over IAM policies - or get a counterexample"
Enter
Sleep 1.5s

Type "iamprover verify --account examples/account.json --invariants examples/invariants.yaml"
Enter
Sleep 4.5s

Type "# A principal with NO direct access can still reach it through AssumeRole chains:"
Enter
Sleep 1.5s

Type "iamprover verify --account examples/chain-account.json --invariants examples/invariants.yaml --closure assume-role"
Enter
Sleep 5s

Type "# exit code 2 on violation - drop it into CI and it fails the PR"
Enter
Sleep 3s

# Windows entry point; keep arguments and exit codes identical to deploy.sh.
& python (Join-Path $PSScriptRoot 'deploy.py') @args
exit $LASTEXITCODE

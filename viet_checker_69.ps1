$ErrorActionPreference = "Stop"

Write-Host "--------Building Jekyll site--------"
bundle exec jekyll build

Write-Host "--------Build completed--------"

Write-Host "--------HTMLProofer checks--------"
bundle exec htmlproofer _site --disable-external --ignore-urls '/^http:\/\/127.0.0.1/,/^http:\/\/0.0.0.0/,/^http:\/\/localhost/'

Write-Host "Passed"

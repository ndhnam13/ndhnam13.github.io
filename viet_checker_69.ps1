$ErrorActionPreference = "Stop"

Write-Host "----------------BUILDING----------------"
bundle exec jekyll build

Write-Host "----------------BUILD COMPLETED----------------"

Write-Host "----------------HTMLPROOFER CHECKS----------------"
bundle exec htmlproofer _site --disable-external --ignore-urls '/^http:\/\/127.0.0.1/,/^http:\/\/0.0.0.0/,/^http:\/\/localhost/'

Write-Host "----------------PASSED----------------"

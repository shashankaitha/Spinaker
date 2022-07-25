name: 'Burp_Suite'

permissions:
  contents: read

jobs:
  Scan:
    name: 'BurpScan'
    runs-on: ubuntu-latest
    #environment: production

    # Use the Bash shell regardless whether the GitHub Actions runner is ubuntu-latest, macos-latest, or windows-latest
    defaults:
      run:
        shell: bash

    steps:
    # java -jar path/to/ci-driver.jar https://your-enterprise-server:8080 --api-key=secret --site-id=7 --min-severity=high --min-confidence=certain --report-file=scan-report.html --report-type=summary
    # burp-suite.awsdev.repsrv.com
    # https://your-enterprise-server.com:8080/sites/<site-id>
    # Changed the site-id accordingly
    - name: Scan using curl
      run: |
         curl 'https://burp-suite.awsdev.repsrv.com/sites/<site-id>'
    
    - name: Scans using the parameter store
      run: |
        java -jar path/to/ci-driver.jar https://your-enterprise-server:8080 --api-key=secret --site-id=7 --min-severity=high --min-confidence=certain --report-file=scan-report.html --report-type=summary

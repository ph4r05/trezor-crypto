#!/bin/bash
echo "COV"
curl -s "https://scan.coverity.com/scripts/travisci_build_coverity_scan.sh" > /tmp/cov.sh

echo "COVThere"
chmod +x /tmp/cov.sh

. /tmp/cov.sh


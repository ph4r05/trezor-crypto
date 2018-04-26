#!/bin/bash
echo "COVERITY SCAN"
curl -s "https://scan.coverity.com/scripts/travisci_build_coverity_scan.sh" > /tmp/cov.sh

echo "COVERITY downloaded"
chmod +x /tmp/cov.sh

. /tmp/cov.sh


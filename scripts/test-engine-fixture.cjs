// Version output of the router binaries used by installer integration tests.
module.exports = function engineFixture(component, release = '${D2K_RELEASE_ID:-dev}', wire = 33) {
  return `#!/bin/sh
if [ "$1" = --version ]; then
    echo "${component} release=${release} wire=${wire}"
    exit 0
fi
exit ${component === 'd2kc' ? 2 : 0}
`;
};

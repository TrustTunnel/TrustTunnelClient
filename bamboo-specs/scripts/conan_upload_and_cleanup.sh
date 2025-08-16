#!/bin/bash

conan remote login art "${bamboo_artifactoryUser}" --password "${bamboo_artifactoryPassword}"
conan upload -r art -c "*" 2>&1 | grep --line-buffered Uploading
echo conan upload finished with status $?
conan remove -c "*" &> /dev/null
conan cache clean &> /dev/null

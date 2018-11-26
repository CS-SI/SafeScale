#!/usr/bin/env bash

echo "Last commit was:" `git show --format="%aE" HEAD | grep @ | grep -v @@`
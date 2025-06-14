#!/bin/bash

git switch main
echo "$1" >version
git add version
git commit -m "Bump version to $1"
git tag "$1"
git push origin main --tags

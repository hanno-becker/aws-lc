#!/bin/bash

GITHUB_SERVER_URL=https://github.com/
GITHUB_REPOSITORY=${GITHUB_REPOSITORY:=pq-code-package/mlkem-native.git}
GITHUB_SHA=${GITHUB_SHA:=HEAD}

TMP=3rd_party
SRC=mlkem

# Check if temporary directory still exists
if [ -d "$TMP" ]; then
    echo "Temporary directory $TMP does already exist -- please remove it before running the importer"
    exit 1
fi

# Check if source directory already exists
if [ -d "$SRC" ]; then
    echo "Source directory or symlink $SRC does already exist -- please remove it before running the importer"
fi

# Create temporary directory
mkdir -p $TMP
pushd $TMP

# Create source directory

# Fetch repository
echo "Fetching repository ..."
git init >/dev/null
git remote add origin $GITHUB_SERVER_URL/$GITHUB_REPOSITORY >/dev/null
git fetch origin --depth 1 $GITHUB_SHA >/dev/null
git checkout FETCH_HEAD >/dev/null

popd

echo "Pull source code from remote repository..."

# Symlink source for now -- eventually this needs to be a hard copy
cp -r $TMP/mlkem $SRC

# Fetch monobuild source file and header
cp $TMP/examples/monolithic_build/mlkem_native_monobuild.c ./

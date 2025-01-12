#!/bin/bash

GITHUB_SERVER_URL=https://github.com/
GITHUB_REPOSITORY=${GITHUB_REPOSITORY:=pq-code-package/mlkem-native.git}
GITHUB_SHA=${GITHUB_SHA:=main}

TMP=tmp_mlkem_native
SRC=mlkem

# Check if temporary directory still exists
if [ -d "$TMP" ]; then
    echo "Temporary directory $TMP does already exist -- removing"
    rm -rf $TMP
fi

# Check if source directory already exists
if [ -d "$SRC" ]; then
    echo "Source directory or symlink $SRC does already exist -- please remove it before re-running the importer"
fi

# Create temporary directory
mkdir -p $TMP
pushd $TMP

# Fetch repository
echo "Fetching repository ..."
git init >/dev/null
git remote add origin $GITHUB_SERVER_URL/$GITHUB_REPOSITORY >/dev/null
git fetch origin --depth 1 $GITHUB_SHA >/dev/null
git checkout FETCH_HEAD >/dev/null

popd

echo "Pull source code from remote repository..."

# Main source tree
cp -r $TMP/mlkem $SRC
cp $TMP/examples/monolithic_build/mlkem_native_monobuild.c ./mlkem_native_bcm.c
# We don't use the x86_64 backends, and provide our own backend metadata
rm -r $SRC/native/x86_64      \
   $SRC/native/x86_64/meta.h  \
   $SRC/fips202/native/x86_64 \
   $SRC/fips202/native/meta.h

echo "Remove temporary artifacts ..."
rm -rf $TMP

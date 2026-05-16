#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BUILD_DIR="$ROOT_DIR/build"
CLASSES_DIR="$BUILD_DIR/classes"
JAR_FILE="$BUILD_DIR/dpi-engine.jar"

rm -rf "$CLASSES_DIR"
mkdir -p "$CLASSES_DIR"

find "$ROOT_DIR/src/main/java" -name '*.java' | sort > "$BUILD_DIR/java-sources.txt"
javac --release 17 -d "$CLASSES_DIR" @"$BUILD_DIR/java-sources.txt"
jar --create --file "$JAR_FILE" --main-class com.packetanalyzer.dpi.Main -C "$CLASSES_DIR" .

echo "Built $JAR_FILE"

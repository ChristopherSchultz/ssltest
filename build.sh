#!/bin/sh

BASE=`dirname "$0"`

mkdir -p "${BASE}/build/classes"

javac -Xlint:-options -source 1.5 -target 1.5 -d "${BASE}/build/classes" $( find "${BASE}"/src/java -name "*.java" )

result=$?

if [ "0" -ne "$result" ] ; then
  echo
  echo "Compile failed (exit code $result). See output above."

  exit
fi

echo "Main-Class: net.christopherschultz.ssltest.SSLTest" > "${BASE}"/build/MANIFEST.MF

jar cfm "${BASE}/build/ssltest.jar" "${BASE}/build/MANIFEST.MF" -C "${BASE}/build/classes" .

echo ssltest.jar has been built in "${BASE}/build/ssltest.jar"

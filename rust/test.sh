#!/bin/sh
TEST_ID=$(curl -X POST 127.0.0.1:3000/scans/ -H "Content-Type: application/json" --data "@examples/discovery.json")
TEST_ID=$(echo $TEST_ID | jq -r)
echo "Test ID: $TEST_ID"
curl -vX POST 127.0.0.1:3000/scans/$TEST_ID -H "Content-Type: application/json" --data '{"action": "start"}'
curl -vX POST 127.0.0.1:3000/scans/$TEST_ID -H "Content-Type: application/json" --data '{"action": "start"}'


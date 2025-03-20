#!/bin/bash

if [[ "$1" == "--migrate" || "$RUN_MIGRATIONS" == "true" ]]; then
    echo "Running database migrations"
    ./efbundle
else
    echo "Skipping database migrations"
fi

echo "Starting application"
dotnet SnowrunnerMergerApi.dll
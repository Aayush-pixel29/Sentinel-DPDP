#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-sentinel-dpdp}"
REGION="${GCP_REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-sentinel-dpdp}"

echo "Deploying $SERVICE_NAME to Cloud Run ($PROJECT_ID / $REGION)..."
gcloud config set project "$PROJECT_ID"
gcloud services enable run.googleapis.com bigquery.googleapis.com aiplatform.googleapis.com

gcloud run deploy "$SERVICE_NAME" \
  --source . \
  --region "$REGION" \
  --allow-unauthenticated \
  --set-env-vars "GOOGLE_CLOUD_PROJECT=$PROJECT_ID,BQ_DATASET=sentinel_dpdp,BQ_TABLE=scan_telemetry"

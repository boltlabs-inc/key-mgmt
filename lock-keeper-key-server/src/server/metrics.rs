use std::sync::Arc;

use metered::ResponseTime;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::LockKeeperServerError;

use super::GeneralMetrics;

#[derive(Default, Debug, Serialize)]
pub struct Metrics {
    pub general_metrics: Arc<GeneralMetrics>,
    pub channel_metrics: Arc<ChannelMetrics>,
    pub operation_metrics: Arc<OperationMetrics>,
}

#[derive(Default, Debug, Serialize)]
pub struct OperationMetrics {
    // Store blob metrics
    pub store_blob_total: ResponseTime,
    pub store_blob_receive_msg: ResponseTime,
    pub store_blob_prepare: ResponseTime,
    pub store_blob_database: ResponseTime,
    pub store_blob_send_msg: ResponseTime,

    // Retrieve blob metrics
    pub retrieve_blob_total: ResponseTime,
    pub retrieve_blob_receive_msg: ResponseTime,
    pub retrieve_blob_database: ResponseTime,
    pub retrieve_blob_prepare: ResponseTime,
    pub retrieve_blob_send_msg: ResponseTime,
}

#[derive(Debug, Default, Serialize)]
pub struct ChannelMetrics {
    pub receive_message: ResponseTime,
    pub receive_into_encrypted: ResponseTime,
    pub receive_decrypt: ResponseTime,
    pub receive_from_message: ResponseTime,
    pub receive_to_result: ResponseTime,

    pub send_to_message: ResponseTime,
    pub send_encrypt: ResponseTime,
    pub send_try_into_message: ResponseTime,
    pub send_message: ResponseTime,
}

impl Metrics {
    pub fn json(&self) -> Result<Value, LockKeeperServerError> {
        let general_metrics = serde_json::to_value(&self.general_metrics)
            .map_err(LockKeeperServerError::SerdeJson)?;
        let channel_metrics = serde_json::to_value(&self.channel_metrics)
            .map_err(LockKeeperServerError::SerdeJson)?;
        let operation_metrics = serde_json::to_value(&self.operation_metrics)
            .map_err(LockKeeperServerError::SerdeJson)?;

        let mut mean_measurements: Map<String, Value> = Map::new();

        if let Value::Object(general) = &general_metrics {
            for (key, value) in general {
                if let Some(mean) = value.pointer("/response_time/mean") {
                    let _ = mean_measurements.insert(key.clone(), mean.clone());
                }
            }
        }

        if let Value::Object(channel) = &channel_metrics {
            for (key, value) in channel {
                if let Some(mean) = value.pointer("/response_time/mean") {
                    let _ = mean_measurements.insert(key.clone(), mean.clone());
                }
            }
        }

        if let Value::Object(operation) = &operation_metrics {
            for (key, value) in operation {
                if let Some(mean) = value.pointer("/response_time/mean") {
                    let _ = mean_measurements.insert(key.clone(), mean.clone());
                }
            }
        }

        let mean_by_function = Value::Object(mean_measurements);

        let json = serde_json::json!({
            "mean_by_function": mean_by_function,
            "general": general_metrics,
            "channel": channel_metrics,
            "operation": operation_metrics,
        });

        Ok(json)
    }
}

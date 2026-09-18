use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};

/// Hard cap on the number of labels (OTLP calls these "attributes") a single
/// metric point may carry.
///
/// Unbounded label sets are the standard way a metrics store dies: every
/// distinct label combination becomes its own series, and cardinality grows
/// multiplicatively per label. Twenty is enough to cover the dimensions a
/// self-hosted, low-traffic deployment actually needs (e.g. `service`,
/// `host`, `method`, `status_code`, `route`) while keeping the worst case
/// for a single point small and bounded, per the project's "bound every
/// buffer" rule.
pub const MAX_METRIC_LABELS: usize = 20;

/// The kind of a metric point.
///
/// OTLP's data model additionally distinguishes monotonic vs. non-monotonic
/// sums and cumulative vs. delta aggregation temporality; we collapse that
/// to the three point kinds errexd cares about. A monotonic, cumulative sum
/// is what most tooling calls a "counter" — that's the only sum shape
/// modeled here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetricKind {
    Counter,
    Gauge,
    Histogram,
}

/// A bounded, string-valued label set attached to a metric point.
///
/// Deviation from OTLP: OTLP attributes are a `repeated KeyValue` where each
/// value is a typed `AnyValue` (string, bool, int, double, array, kvlist,
/// bytes). We only support string values in a flat map. A non-string
/// attribute value must be stringified (or rejected) by the ingest layer
/// that translates an OTLP payload into this type.
///
/// The cardinality cap ([`MAX_METRIC_LABELS`]) is enforced by construction —
/// both `TryFrom<BTreeMap<String, String>>` and `Deserialize` reject an
/// over-cap map — so a caller cannot bypass it by constructing the map
/// directly.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct MetricLabels(BTreeMap<String, String>);

impl MetricLabels {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

impl TryFrom<BTreeMap<String, String>> for MetricLabels {
    type Error = crate::error::ProtoError;

    fn try_from(map: BTreeMap<String, String>) -> Result<Self, Self::Error> {
        if map.len() > MAX_METRIC_LABELS {
            return Err(crate::error::ProtoError::InvalidMetric(format!(
                "metric point carries {} labels, exceeding the cap of {MAX_METRIC_LABELS}",
                map.len()
            )));
        }
        Ok(Self(map))
    }
}

impl<'de> Deserialize<'de> for MetricLabels {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let map = BTreeMap::<String, String>::deserialize(deserializer)?;
        MetricLabels::try_from(map).map_err(D::Error::custom)
    }
}

/// A single OTLP-flavored metric observation.
///
/// Field names and semantics follow OTLP's metrics data model so an
/// OTLP/JSON payload maps onto this type without a translation layer, with
/// the following deviations for simplicity (kept here, not scattered across
/// ingest):
///
/// - OTLP nests points under
///   `resourceMetrics[].scopeMetrics[].metrics[].{gauge,sum,histogram}.dataPoints[]`;
///   this flattens to one point per struct, with `kind` standing in for the
///   oneof wrapper. The names are not identical: OTLP's wrapper keys are
///   `gauge`, `sum` and `histogram`, so an ingest layer reading OTLP/JSON
///   must map `sum` (monotonic, cumulative) onto [`MetricKind::Counter`].
///   `gauge` and `histogram` match by name.
/// - OTLP encodes `timeUnixNano` as a decimal string, since JSON numbers
///   cannot losslessly hold a 64-bit nanosecond timestamp. We use
///   `DateTime<Utc>` for consistency with [`crate::event::Event::timestamp`];
///   converting an OTLP nanosecond string into this is the ingest layer's job.
/// - OTLP's `HistogramDataPoint` carries bucket counts, explicit bounds, and
///   min/max; none of that is modeled. `value` on a histogram point is a
///   single raw observation, not a pre-aggregated bucket set — bucketing is
///   ingest/storage's job, not the wire type's.
/// - See [`MetricLabels`] for the label/attribute deviation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    pub name: String,
    pub kind: MetricKind,
    pub value: f64,
    pub timestamp: DateTime<Utc>,
    #[serde(default)]
    pub labels: MetricLabels,
}

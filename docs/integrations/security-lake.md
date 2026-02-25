# AWS Security Lake Integration

## OCSF Output Format

nexora-cli outputs OCSF 1.1.0 in **JSONL format** for SIEM ingestion (Splunk, Elastic, Chronicle, etc.).

## AWS Security Lake Requirements

AWS Security Lake **custom sources** require OCSF schema in **Apache Parquet format**, not JSONL.

To ingest nexora-cli findings into Security Lake, you need a conversion pipeline:

### Option 1: Lambda + S3 Pipeline

```bash
# 1. nexora-cli outputs OCSF JSONL
nexora scan workflows --path .github/workflows/ --format ocsf > findings.jsonl

# 2. Upload to S3 staging bucket
aws s3 cp findings.jsonl s3://your-staging-bucket/nexora/

# 3. Lambda converts JSONL → Parquet using PyArrow
# (See example Lambda function below)

# 4. Security Lake ingests from Parquet bucket
```

### Option 2: Glue ETL Job

```python
import sys
from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job

sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session

# Read JSONL from S3
df = spark.read.json("s3://staging-bucket/nexora/*.jsonl")

# Write as Parquet to Security Lake custom source bucket
df.write.mode("append").parquet("s3://security-lake-custom-source/nexora/")
```

### Option 3: Direct Parquet Output (Future)

We're evaluating adding `--format ocsf-parquet` in a future release. Track progress in [issue #XX](https://github.com/Nexora-NHI/nexora-cli/issues/XX).

## SIEM Integration (No Conversion Needed)

For **Splunk, Elastic, Sumo Logic, Chronicle**, use OCSF JSONL directly:

```bash
nexora scan workflows --path .github/workflows/ --format ocsf | \
  curl -X POST https://your-siem-endpoint/ingest \
    -H "Content-Type: application/x-ndjson" \
    --data-binary @-
```

## References

- [AWS Security Lake Custom Sources](https://docs.aws.amazon.com/security-lake/latest/userguide/custom-sources.html)
- [OCSF Schema](https://schema.ocsf.io/)
- [Apache Parquet Format](https://parquet.apache.org/)

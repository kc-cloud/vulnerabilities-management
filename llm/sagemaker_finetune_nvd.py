#!/usr/bin/env python3
"""
sagemaker_finetune_nvd.py

Orchestrates:
  - converts NVD JSON feed(s) into Q/A supervised examples,
  - uploads training data + a training entry script to S3,
  - launches a SageMaker HuggingFace Estimator to fine-tune a small seq2seq model
    for answering vulnerability/NVD questions.

Before running:
  pip install sagemaker boto3 datasets transformers accelerate sentencepiece
  Ensure AWS credentials & permissions to create SageMaker training jobs and S3 access.
"""
import os
import json
import gzip
import glob
import uuid
import time
from pathlib import Path
import io

import boto3
import sagemaker
from sagemaker.huggingface import HuggingFace
import boto3
from sagemaker import get_execution_role
from sagemaker.model import Model

# Parameters
REGION = "us-east-1"                   # change if needed
MODEL_PACKAGE_GROUP_NAME = "nvd-llm-models"  # Change as needed
MODEL_PACKAGE_GROUP_DESC = "NVD vulnerability QA LLM models"
MODEL_NAME = f"nvd-llm-{int(time.time())}"  # unique model name
MODEL_PACKAGE_DESC = "Fine-tuned Flan-T5 model on NVD data"

sm_client = boto3.client("sagemaker", region_name=REGION)

# ---------------------------
# === USER CONFIGURATION ====
# ---------------------------
LOCAL_NVD_DIR = "nvd_feeds"           # where nvdcve-2.0-YYYY.json (or extracted .json) are stored
S3_BUCKET = "your-sagemaker-bucket"   # <- change: your bucket name (must exist)
S3_PREFIX = "nvd-llm-training"        # S3 prefix to hold data and training artifacts
ROLE_ARN = None                        # if None, script will try sagemaker.get_execution_role()
REGION = "us-east-1"                   # change if needed

# Model / training choices (change for larger/smaller models)
HF_MODEL_ID = "google/flan-t5-base"    # good starter seq2seq model (small)
INSTANCE_TYPE = "ml.p3.2xlarge"        # pick based on budget; can be ml.g5.xlarge or ml.p3.2xlarge
INSTANCE_COUNT = 1
EPOCHS = 3
BATCH_SIZE = 8
LEARNING_RATE = 5e-5
MAX_SEQ_LENGTH = 512

# Whether to register the model into SageMaker Model Registry (optional)
LOCAL_TEST = True
REGISTER_MODEL = False
MODEL_PACKAGE_GROUP_NAME = "nvd-llm-models"  # used if REGISTER_MODEL True

# ---------------------------
# === Helper functions  =====
# ---------------------------
def ensure_bucket_exists(s3_client, bucket):
    try:
        s3_client.head_bucket(Bucket=bucket)
    except Exception as e:
        raise RuntimeError(f"S3 bucket '{bucket}' is not accessible or does not exist: {e}")

def read_nvd_json_files(local_dir):
    """
    Read any .json or .json.gz CVE files in local_dir and yield CVE dicts.
    """
    patterns = [os.path.join(local_dir, "*.json"), os.path.join(local_dir, "*.json.gz")]
    for pattern in patterns:
        for path in glob.glob(pattern):
            if path.endswith(".gz"):
                with gzip.open(path, "rt", encoding="utf-8") as fh:
                    data = json.load(fh)
            else:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            # NVD JSON2.0 structure: top-level 'vulnerabilities' list of objects each with 'cve'
            if "vulnerabilities" in data:
                for item in data["vulnerabilities"]:
                    yield item.get("cve", {})
            else:
                # fallback for older format: maybe top-level 'CVE_Items'
                if "CVE_Items" in data:
                    for item in data["CVE_Items"]:
                        yield item.get("cve", {})
                else:
                    # unknown structure — skip
                    continue

def cve_to_training_examples(cve):
    """
    Convert a single CVE entry (NVD CVE JSON 'cve' block) to one or more training examples.
    We'll produce short Q/A pairs where:
      - input: "What is CVE-YYYY-NNNN? Context: <summary and affected products>"
      - target: short summary of the vulnerability (from description) + metadata (severity)
    You may expand this function to produce many more QA variations.
    """
    examples = []
    metadata = {}
    cve_id = None
    # typical structure: cve['CVE_data_meta']['ID'] OR cve['id']
    if "CVE_data_meta" in cve and "ID" in cve["CVE_data_meta"]:
        cve_id = cve["CVE_data_meta"]["ID"]
    elif "id" in cve:
        cve_id = cve["id"]
    else:
        # try to extract from other fields
        pass

    # description text — choose first english description if present
    description = ""
    desc_data = cve.get("description", {})
    if isinstance(desc_data, dict) and "description_data" in desc_data:
        for dd in desc_data["description_data"]:
            if dd.get("lang", "") == "en":
                description = dd.get("value", "")
                break
    elif isinstance(desc_data, str):
        description = desc_data

    # affected products from configurations (best-effort)
    affected = []
    nodes = cve.get("configurations", {}).get("nodes", []) if "configurations" in cve else []
    # NVD top-level format sometimes puts 'configurations' outside cve in 'vulnerabilities' wrapper;
    # keep it simple — we will also pick from 'vendors' if present
    # fallback: look into 'affects' -> 'vendor' -> 'vendor_data'
    affects = cve.get("affects", {})
    try:
        if affects and isinstance(affects, dict):
            vendors = affects.get("vendor", {}).get("vendor_data", [])
            for vd in vendors:
                pname = vd.get("product", {}).get("product_data", [])
                for p in pname:
                    affected.append(p.get("product_name", ""))
    except Exception:
        pass

    # severity: try to extract CVSS v3 score/narrative
    severity = None
    impact = cve.get("impact", {})
    if impact:
        # different NVD formats: maybe impact['baseMetricV3']['cvssV3']['baseScore']
        if "baseMetricV3" in impact and "cvssV3" in impact["baseMetricV3"]:
            severity = impact["baseMetricV3"]["cvssV3"].get("baseScore")
        elif "baseMetricV2" in impact and "cvssV2" in impact["baseMetricV2"]:
            severity = impact["baseMetricV2"]["cvssV2"].get("baseScore")

    # Build a short context: include ID, one-line summary, affected list, severity
    parts = []
    if cve_id:
        parts.append(f"ID: {cve_id}")
    if description:
        # take first sentence or up to 300 chars
        first_sentence = description.split(".")[0].strip()
        parts.append(f"Summary: {first_sentence}")
    if affected:
        parts.append("Affected: " + ", ".join(affected[:6]))
    if severity is not None:
        parts.append(f"SeverityScore: {severity}")

    context = " | ".join(parts)
    if not context:
        return examples

    # Construct a few question templates
    q_templates = [
        "What is {id}?",
        "Give me a short summary of {id}.",
        "Summarize the vulnerability {id}.",
        "What does {id} affect?",
    ]
    # answer: include slightly longer summary (first 2 sentences) plus severity if present
    answer_sentences = description.split(".")
    ans = ""
    if len(answer_sentences) >= 2:
        ans = (answer_sentences[0].strip() + ". " + answer_sentences[1].strip() + ".").strip()
    else:
        ans = description.strip()
    if severity is not None:
        ans = ans + f" SeverityScore: {severity}."

    for qt in q_templates:
        q = qt.format(id=cve_id) if cve_id else qt.format(id="this CVE")
        # input format: we feed a "question + context" so the model can learn to use context.
        inp = f"Question: {q}\nContext: {context}"
        examples.append({"input": inp, "target": ans})

    return examples

def build_training_dataset_jsonl(local_nvd_dir, out_path, max_examples=None):
    """
    Produce a JSONL training file of {"input":..., "target":...} entries.
    """
    cnt = 0
    with open(out_path, "w", encoding="utf-8") as outf:
        for cve in read_nvd_json_files(local_nvd_dir):
            exs = cve_to_training_examples(cve)
            for ex in exs:
                outf.write(json.dumps(ex, ensure_ascii=False) + "\n")
                cnt += 1
                if max_examples and cnt >= max_examples:
                    print(f"[INFO] reached max_examples={max_examples}")
                    return cnt
    return cnt

# ---------------------------
# === Training entry script =
# ---------------------------
TRAINING_SCRIPT = r"""
# training_script.py - HuggingFace Trainer entry point for SageMaker
import os
import argparse
import json
from datasets import load_dataset, Dataset
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM, DataCollatorForSeq2Seq, Seq2SeqTrainingArguments, Seq2SeqTrainer

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model_name_or_path", type=str, required=True)
    parser.add_argument("--train_file", type=str, required=True)
    parser.add_argument("--output_dir", type=str, default="/opt/ml/model")
    parser.add_argument("--per_device_train_batch_size", type=int, default=8)
    parser.add_argument("--num_train_epochs", type=int, default=3)
    parser.add_argument("--learning_rate", type=float, default=5e-5)
    parser.add_argument("--max_source_length", type=int, default=512)
    parser.add_argument("--max_target_length", type=int, default=256)
    args = parser.parse_args()
    return args

def main():
    args = parse_args()
    # load dataset from jsonlines file
    raw = load_dataset("json", data_files={"train": args.train_file})["train"]

    tokenizer = AutoTokenizer.from_pretrained(args.model_name_or_path, use_fast=True)
    model = AutoModelForSeq2SeqLM.from_pretrained(args.model_name_or_path)

    def preprocess(batch):
        inputs = [ex["input"] for ex in batch]
        targets = [ex["target"] for ex in batch]
        model_inputs = tokenizer(inputs, max_length=args.max_source_length, truncation=True, padding="max_length")
        labels = tokenizer(targets, max_length=args.max_target_length, truncation=True, padding="max_length")
        model_inputs["labels"] = labels["input_ids"]
        return model_inputs

    tokenized = raw.map(preprocess, batched=True, remove_columns=raw.column_names)
    data_collator = DataCollatorForSeq2Seq(tokenizer, model=model)

    training_args = Seq2SeqTrainingArguments(
        output_dir=args.output_dir,
        per_device_train_batch_size=args.per_device_train_batch_size,
        num_train_epochs=args.num_train_epochs,
        learning_rate=args.learning_rate,
        logging_steps=100,
        save_steps=500,
        fp16=True if os.getenv("SM_NUM_GPUS", "0") != "0" else False,
        prediction_loss_only=True,
        remove_unused_columns=True,
        save_total_limit=2,
    )

    trainer = Seq2SeqTrainer(
        model=model,
        args=training_args,
        train_dataset=tokenized,
        data_collator=data_collator,
        tokenizer=tokenizer,
    )

    trainer.train()
    trainer.save_model(args.output_dir)

if __name__ == "__main__":
    main()
"""

# ---------------------------
# === Orchestration =========
# ---------------------------
def main():
    # Setup AWS / sagemaker sess
    boto_sess = boto3.Session(region_name=REGION)
    s3 = boto_sess.client("s3")
    sm = sagemaker.Session(boto_session=boto_sess)
    try:
        role = ROLE_ARN or sagemaker.get_execution_role()
    except Exception:
        # fallback: if running locally, user must supply ROLE_ARN
        if ROLE_ARN:
            role = ROLE_ARN
        else:
            raise RuntimeError("Unable to determine SageMaker role. Set ROLE_ARN at top of this script when running outside SageMaker.")

    ensure_bucket_exists(s3, S3_BUCKET)

    # Build training dataset JSONL
    timestamp = int(time.time())
    local_out_dir = Path("nvd_training_build")
    local_out_dir.mkdir(parents=True, exist_ok=True)
    train_jsonl = local_out_dir / f"nvd_train_{timestamp}.jsonl"

    print("[INFO] building training dataset JSONL from local NVD files...")
    total = build_training_dataset_jsonl(LOCAL_NVD_DIR, str(train_jsonl))
    if total == 0:
        raise RuntimeError(f"No training examples produced — check that '{LOCAL_NVD_DIR}' contains NVD JSON files.")
    print(f"[INFO] produced {total} training examples at {train_jsonl}")

    # write the training entry script to disk
    entry_script_path = local_out_dir / "training_script.py"
    entry_script_path.write_text(TRAINING_SCRIPT, encoding="utf-8")

    # Upload training data and entry script to S3
    s3_data_prefix = f"{S3_PREFIX}/input/{timestamp}"
    s3_train_key = f"{s3_data_prefix}/{train_jsonl.name}"
    s3_script_key = f"{s3_data_prefix}/training_script.py"

    print(f"[INFO] uploading training file to s3://{S3_BUCKET}/{s3_train_key}")
    s3.upload_file(str(train_jsonl), S3_BUCKET, s3_train_key)
    print(f"[INFO] uploading training script to s3://{S3_BUCKET}/{s3_script_key}")
    s3.upload_file(str(entry_script_path), S3_BUCKET, s3_script_key)

    s3_train_uri = f"s3://{S3_BUCKET}/{s3_train_key}"
    s3_script_uri = f"s3://{S3_BUCKET}/{s3_script_key}"

    # Create a HuggingFace estimator
    hyperparameters = {
        "model_name_or_path": HF_MODEL_ID,
        "train_file": s3_train_uri,
        "per_device_train_batch_size": BATCH_SIZE,
        "num_train_epochs": EPOCHS,
        "learning_rate": LEARNING_RATE,
        "max_source_length": MAX_SEQ_LENGTH,
        "max_target_length": 256,
    }

    # HuggingFace image config:
    huggingface_estimator = HuggingFace(
        entry_point="training_script.py",
        source_dir=str(local_out_dir),  # required - SageMaker will upload these files
        instance_type=INSTANCE_TYPE,
        instance_count=INSTANCE_COUNT,
        role=role,
        transformers_version="4.31.0",        # adjust if you prefer another version
        pytorch_version="2.2.0",              # adjust as needed
        py_version="py310",
        hyperparameters=hyperparameters,
        base_job_name="nvd-llm-finetune",
        sagemaker_session=sm,
    )

    # Kick off training job
    print("[INFO] starting SageMaker training job (this will create a training job and run it)...")
    huggingface_estimator.fit({"train": s3_train_uri}, wait=True)

    # After training completes, model artifact is at huggingface_estimator.model_data (S3 URI)
    print("[DONE] Training job complete.")
    print("Model artifact (S3):", huggingface_estimator.model_data)
    HF_IMAGE_URI = huggingface_estimator.training_image_uri()
    if REGISTER_MODEL:
        try:
            sm_client.create_model_package_group(
                ModelPackageGroupName=MODEL_PACKAGE_GROUP_NAME,
                ModelPackageGroupDescription=MODEL_PACKAGE_GROUP_DESC
            )
            print(f"[INFO] ModelPackageGroup '{MODEL_PACKAGE_GROUP_NAME}' created.")
        except sm_client.exceptions.ResourceInUse:
            print(f"[INFO] ModelPackageGroup '{MODEL_PACKAGE_GROUP_NAME}' already exists.")

        # 2️⃣ Create a SageMaker Model (needed for registration)
        role_arn = ROLE_ARN or get_execution_role()
        model = Model(
            image_uri=HF_IMAGE_URI,
            model_data=huggingface_estimator.model_data,  # S3 path of trained model
            role=role_arn,
            sagemaker_session=sm,
            name=MODEL_NAME,
        )

        # 3️⃣ Register the model in the registry
        response = model.register(
            content_types=["application/json"],
            response_types=["application/json"],
            inference_instances=["ml.m5.large", "ml.g5.xlarge"],
            transform_instances=["ml.m5.large"],
            model_package_group_name=MODEL_PACKAGE_GROUP_NAME,
            model_package_description=MODEL_PACKAGE_DESC,
            approval_status="PendingManualApproval",  # you can set "Approved" if you want
        )

        print("[INFO] Model registration request submitted.")
        print("ModelPackageArn:", response["ModelPackageArn"])

if __name__ == "__main__":
    main()

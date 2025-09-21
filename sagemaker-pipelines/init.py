import sagemaker
import boto3
import os
from sagemaker.workflow.pipeline import Pipeline
from sagemaker.workflow.steps import ProcessingStep, TrainingStep, CacheConfig
from sagemaker.workflow.model_step import ModelStep
from sagemaker.processing import ScriptProcessor, ProcessingInput, ProcessingOutput
from sagemaker.huggingface import HuggingFace, HuggingFaceModel
from sagemaker.workflow.parameters import ParameterString

# --- SageMaker Session and Role Setup ---
sess = sagemaker.Session()
# sagemaker_session = sagemaker.Session()
bucket = sess.default_bucket()  # Or specify your own S3 bucket
role = sagemaker.get_execution_role()
region = boto3.Session().region_name

print(f"SageMaker Role ARN: {role}")
print(f"SageMaker Session region: {region}")
print(f"S3 bucket: {bucket}")

# --- Pipeline Configuration ---
# Use a cache to speed up pipeline execution during development
cache_config = CacheConfig(enable_caching=True, expire_after="30d")

# Define a name for the model package group in the registry
model_package_group_name = "HuggingFace-Finetune-OPT-Pipeline"

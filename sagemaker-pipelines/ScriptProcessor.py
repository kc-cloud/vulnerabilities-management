from sagemaker.sklearn.processing import SKLearnProcessor

# Define the processor
sklearn_processor = SKLearnProcessor(
    framework_version="1.2-1",
    instance_type="ml.m5.xlarge",
    instance_count=1,
    base_job_name="hf-llm-data-prep",
    role=role,
)

# Define the pipeline step
step_process = ProcessingStep(
    name="PreprocessHuggingFaceData",
    processor=sklearn_processor,
    inputs=[],
    outputs=[
        ProcessingOutput(output_name="train", source="/opt/ml/processing/train"),
        ProcessingOutput(output_name="test", source="/opt/ml/processing/test"),
    ],
    code="preprocess.py",
    cache_config=cache_config,
)

print("Processing step defined.")


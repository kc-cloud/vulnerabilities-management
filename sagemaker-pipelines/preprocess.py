
import argparse
import os
import logging
import pandas as pd
from datasets import load_dataset
from transformers import AutoTokenizer

# Set up logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def preprocess_data(data, tokenizer):
    """Tokenize the dialogue and summary."""
    inputs = ["summarize: " + dialogue for dialogue in data["dialogue"]]
    model_inputs = tokenizer(inputs, max_length=1024, truncation=True, padding="max_length")
    
    # Setup the tokenizer for targets
    labels = tokenizer(text_target=data["summary"], max_length=128, truncation=True, padding="max_length")

    model_inputs["labels"] = labels["input_ids"]
    return model_inputs

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model_id", type=str, default="facebook/opt-125m")
    parser.add_argument("--dataset_name", type=str, default="samsum")
    args, _ = parser.parse_known_args()

    logger.info("Starting data preprocessing...")

    # Define output paths
    train_output_path = "/opt/ml/processing/train"
    test_output_path = "/opt/ml/processing/test"
    
    os.makedirs(train_output_path, exist_ok=True)
    os.makedirs(test_output_path, exist_ok=True)

    # Load dataset from Hugging Face Hub
    dataset = load_dataset(args.dataset_name)
    logger.info(f"Dataset loaded: {dataset}")

    # Load tokenizer
    tokenizer = AutoTokenizer.from_pretrained(args.model_id)
    
    # Preprocess and save datasets
    train_dataset = dataset["train"].map(lambda data: preprocess_data(data, tokenizer), batched=True)
    test_dataset = dataset["test"].map(lambda data: preprocess_data(data, tokenizer), batched=True)

    logger.info("Saving processed datasets to disk...")
    train_dataset.save_to_disk(train_output_path)
    test_dataset.save_to_disk(test_output_path)
    
    logger.info("Preprocessing complete.")

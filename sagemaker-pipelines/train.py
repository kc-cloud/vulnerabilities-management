
import argparse
import os
import logging
from transformers import Trainer, TrainingArguments
from smexperiments.tracker import Tracker

# (Import other necessary libraries like torch, datasets, etc.)

def main():
    parser = argparse.ArgumentParser()
    # Your usual script arguments
    parser.add_argument("--epochs", type=int, default=1)
    parser.add_argument("--learning_rate", type=float, default=3e-4)
    parser.add_argument("--model_id", type=str)
    # SageMaker environment arguments
    parser.add_argument("--model_dir", type=str, default=os.environ.get("SM_MODEL_DIR"))
    
    args, _ = parser.parse_known_args()

    # --- SageMaker Experiments Integration ---
    # 1. Load the tracker from the file path passed by SageMaker
    tracker = Tracker.load()

    # 2. Log hyperparameters
    tracker.log_parameters({
        "learning_rate": args.learning_rate,
        "epochs": args.epochs,
        "model_id": args.model_id
    })
    
    # --- Load your dataset and model here ---
    # ... (your model and data loading code) ...

    # --- Define a custom callback for the Trainer to log metrics ---
    from transformers.trainer_callback import TrainerCallback

    class ExperimentTrackerCallback(TrainerCallback):
        def on_log(self, args, state, control, logs=None, **kwargs):
            if state.is_world_process_zero:  # Only log on the main process
                for key, value in logs.items():
                    if isinstance(value, (int, float)):
                        # 3. Log metrics during training
                        tracker.log_metric(key, value, step=state.global_step)

    # --- Set up Trainer ---
    training_args = TrainingArguments(
        output_dir=args.model_dir,
        num_train_epochs=args.epochs,
        learning_rate=args.learning_rate,
        # ... other training arguments
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        callbacks=[ExperimentTrackerCallback()], # Add the callback here
    )

    # --- Start Training ---
    trainer.train()

    # --- Save the model ---
    trainer.save_model(args.model_dir)

    # 4. (Optional) Log output artifacts like a confusion matrix or config file
    # tracker.log_output_file("path/to/your/file.txt", "output_files")

    # 5. Close the tracker
    tracker.close()

if __name__ == "__main__":
    main()

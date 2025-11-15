
```
python training_script.py \
    --model_name_or_path google/flan-t5-small \
    --train_file ./nvd_train.jsonl \
    --num_train_epochs 1 \
    --per_device_train_batch_size 2 \
    --output_dir ./local_test_model

```
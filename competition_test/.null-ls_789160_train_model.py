#!/usr/bin/env python3
"""
Training script for the Advanced IDS Model
Run this BEFORE the competition to pre-train your model

Usage: python3 train_model.py
"""

import sys
from pathlib import Path

from advanced_ids import AdvancedIDSModel


def main():
    # Training data files (adjust paths as needed)
    training_csv = "flowkeys_training_labeled_enc.csv"

    # Check if training data exists
    if not Path(training_csv).exists():
        print(f"Error: Training file '{training_csv}' not found")
        print("Please ensure you have the training data in the current directory:")
        print("- flowkeys_training_labeled_enc.csv")
        sys.exit(1)

    print("=== Advanced IDS Model Training ===")
    print(f"Training data: {training_csv}")

    # Create and train model
    ids = AdvancedIDSModel()

    try:
        # Train the model with hyperparameter optimization
        ids.train(training_csv)

        # Save the trained model
        ids.save_model("trained_ids_model.pkl")

        print("\n=== Training Complete ===")
        print("Model saved as: trained_ids_model.pkl")
        print("You can now use this model in the competition!")

    except Exception as e:
        print(f"Training failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

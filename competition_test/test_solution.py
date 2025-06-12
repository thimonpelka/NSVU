#!/usr/bin/env python3
"""
Test and validation script for the IDS solution
Use this to validate your solution before submission
"""

import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd


class SolutionValidator:
    """Validates the IDS solution against competition requirements"""

    def __init__(self):
        self.required_files = [
            "run.sh",
            "advanced_ids.py",
            "trained_ids_model.pkl",
            "4tuple_bidi.json",
        ]

    def check_files(self):
        """Check if all required files exist"""
        print("=== File Check ===")
        missing_files = []

        for file in self.required_files:
            if Path(file).exists():
                print(f"✓ {file}")
            else:
                print(f"✗ {file}")
                missing_files.append(file)

        if missing_files:
            print(f"\nMissing files: {missing_files}")
            return False

        # Check if run.sh is executable
        if not Path("run.sh").stat().st_mode & 0o111:
            print("✗ run.sh is not executable")
            print("Run: chmod +x run.sh")
            return False

        print("✓ All required files present and executable")
        return True

    def validate_goflows_config(self):
        """Validate Go-Flows configuration"""
        print("\n=== Go-Flows Configuration Check ===")

        try:
            import json

            with open("4tuple_bidi.json", "r") as f:
                config = json.load(f)

            flows_config = config.get("flows", {})

            # Check required fields
            required_fields = {
                "active_timeout": 1000,
                "idle_timeout": 1000,
                "bidirectional": True,
                "key_features": [
                    "sourceIPAddress",
                    "destinationIPAddress",
                    "sourceTransportPort",
                    "destinationTransportPort",
                ],
            }

            for field, expected_value in required_fields.items():
                actual_value = flows_config.get(field)
                if actual_value == expected_value:
                    print(f"✓ {field}: {actual_value}")
                else:
                    print(f"✗ {field}: expected {
                          expected_value}, got {actual_value}")
                    return False

            print("✓ Go-Flows configuration valid")
            return True

        except Exception as e:
            print(f"✗ Error reading Go-Flows config: {e}")
            return False

    def test_execution(self, test_pcap=None):
        """Test the execution pipeline"""
        print("\n=== Execution Test ===")

        if test_pcap is None:
            print("No test PCAP provided - skipping execution test")
            print("To test execution, provide a PCAP file:")
            print("python3 test_solution.py --pcap <test.pcap>")
            return True

        if not Path(test_pcap).exists():
            print(f"✗ Test PCAP file not found: {test_pcap}")
            return False

        try:
            print(f"Testing with: {test_pcap}")
            start_time = time.time()

            # Run the solution
            result = subprocess.run(
                ["./run.sh", test_pcap],
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
            )

            execution_time = time.time() - start_time
            print(f"Execution time: {execution_time:.2f} seconds")

            # Check execution time limits
            if execution_time > 600:
                print("✗ Execution time exceeded 600 seconds (-2 points)")
            elif execution_time > 600:
                print("✗ Execution time exceeded 600 seconds (-1 point)")
            else:
                print("✓ Execution time within limits")

            # Check if execution was successful
            if result.returncode != 0:
                print(f"✗ Execution failed with return code: {
                      result.returncode}")
                print(f"STDERR: {result.stderr}")
                return False

            print("✓ Execution completed successfully")
            return True

        except subprocess.TimeoutExpired:
            print("✗ Execution timed out (>600 seconds)")
            return False
        except Exception as e:
            print(f"✗ Execution error: {e}")
            return False

    def validate_output(self):
        """Validate the output format"""
        print("\n=== Output Validation ===")

        if not Path("output.csv").exists():
            print("✗ output.csv not found")
            return False

        try:
            df = pd.read_csv("output.csv")
            print(f"✓ Output file loaded: {len(df)} rows")

            # Check required columns
            required_columns = [
                "flowStartMilliseconds",
                "sourceIPAddress",
                "destinationIPAddress",
                "sourceTransportPort",
                "destinationTransportPort",
                "Binary_Label",
                "Attack_Type_enc",
                "prediction",
            ]

            missing_columns = []
            for col in required_columns:
                if col in df.columns:
                    print(f"✓ Column: {col}")
                else:
                    print(f"✗ Missing column: {col}")
                    missing_columns.append(col)

            if missing_columns:
                print(f"Missing columns: {missing_columns}")
                return False

            # Validate data types and values
            binary_labels = df["Binary_Label"].unique()
            if not all(label in [0, 1] for label in binary_labels):
                print(f"✗ Invalid Binary_Label values: {binary_labels}")
                return False
            print(f"✓ Binary_Label values: {binary_labels}")

            # Check attack types
            attack_types = df["Attack_Type_enc"].unique()
            valid_attacks = ["Normal", "C1", "C2",
                             "C3", "C4", "C5", "C6", "C7", "C8"]
            invalid_attacks = [
                att for att in attack_types if att not in valid_attacks]

            if invalid_attacks:
                print(f"✗ Invalid attack types: {invalid_attacks}")
                return False
            print(f"✓ Attack types: {list(attack_types)}")

            # Summary statistics
            normal_count = len(df[df["Binary_Label"] == 0])
            attack_count = len(df[df["Binary_Label"] == 1])
            print(f"✓ Normal flows: {normal_count}")
            print(f"✓ Attack flows: {attack_count}")

            if attack_count > 0:
                attack_distribution = df[df["Binary_Label"] == 1][
                    "Attack_Type_enc"
                ].value_counts()
                print("✓ Attack distribution:")
                for attack, count in attack_distribution.items():
                    print(f"  {attack}: {count}")

            print("✓ Output format validation passed")
            return True

        except Exception as e:
            print(f"✗ Error validating output: {e}")
            return False

    def run_full_validation(self, test_pcap=None):
        """Run complete validation suite"""
        print("=== NetSec Lab Competition Solution Validator ===\n")

        checks = [
            ("File Check", self.check_files),
            ("Go-Flows Config", self.validate_goflows_config),
            ("Execution Test", lambda: self.test_execution(test_pcap)),
        ]

        results = []
        for check_name, check_func in checks:
            result = check_func()
            results.append((check_name, result))

        # Validate output only if execution test was run and passed
        if test_pcap and results[-1][1]:  # If execution test passed
            output_result = self.validate_output()
            results.append(("Output Validation", output_result))

        # Summary
        print("\n=== Validation Summary ===")
        all_passed = True
        for check_name, passed in results:
            status = "PASS" if passed else "FAIL"
            print(f"{check_name}: {status}")
            if not passed:
                all_passed = False

        if all_passed:
            print("\n🎉 All validations passed! Your solution is ready for submission.")
        else:
            print(
                "\n❌ Some validations failed. Please fix the issues before submission."
            )

        return all_passed


def main():
    """Main function"""
    validator = SolutionValidator()

    # Check for test PCAP argument
    test_pcap = None
    if len(sys.argv) > 1:
        if sys.argv[1] == "--pcap" and len(sys.argv) > 2:
            test_pcap = sys.argv[2]
        else:
            test_pcap = sys.argv[1]

    # Run validation
    success = validator.run_full_validation(test_pcap)

    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()

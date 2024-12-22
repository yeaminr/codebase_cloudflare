import yaml
import os
import argparse
from jsonschema import validate, ValidationError


def parse_argument():
    """
    Parse command line arguments.

    Returns:
        tuple: A tuple containing the paths to the schema YAML file and the input YAML file.
    """
    parser = argparse.ArgumentParser(description="Validate YAML file against schema")
    parser.add_argument("schema_yaml", help="Path to the schema YAML file")
    parser.add_argument("input_yaml", help="Path to the tenant YAML file")
    args = parser.parse_args()
    schema_yaml = args.schema_yaml
    input_yaml = args.input_yaml
    if not os.path.exists(schema_yaml):
        print(f"Schema yaml {schema_yaml} file does not exist")
        exit(1)
    if not os.path.exists(input_yaml):
        print(f"Input yaml {input_yaml} file does not exist")
        exit(1)
    return schema_yaml, input_yaml


def load_yaml(yaml_file):
    """
    Load YAML file.

    Args:
        yaml_file (str): Path to the YAML file.

    Returns:
        dict: The loaded YAML data.

    Raises:
        yaml.YAMLError: If there is an error loading the YAML file.
    """
    try:
        with open(yaml_file, "r") as input:
            return yaml.safe_load(input)
    except yaml.YAMLError as e:
        print(f"Error loading {yaml_file} file : {e}")
        exit(1)


def validate_yaml(schema, data):
    """
    Validate YAML data against a schema.

    Args:
        schema (dict): The schema to validate against.
        data (dict): The YAML data to validate.

    Raises:
        SystemExit: If the YAML data is not valid.
    """
    try:
        validate(data, schema)
    except ValidationError as e:
        print(f"ValidationError: {e}")
        exit(1)
    print("YAML is valid")


def main():
    """
    Main function.

    Parses command line arguments, loads the schema and input YAML files,
    and validates the input YAML against the schema.
    """
    schema_yaml, input_yaml = parse_argument()
    schema = load_yaml(schema_yaml)
    data = load_yaml(input_yaml)
    validate_yaml(schema, data)


if __name__ == "__main__":
    main()

# Scripts

## List of scripts
- YAML Validator

### YAML Validator
The YAML validation is performed by the `yaml_validator.py` python script. The purpose of this script is to ensure that the validate the input YAML file against the provided schema yaml. The validation is performed using the `cerberus` python package.

##### Locally
- Navigate to src folder
- Set up a virtual environment `python3 -m venv venv`
- Activate the venv `source bin/venv/activate`
- Install dependencies `pip3 install -r requirements.txt`
- Run the python script using schema.yaml & input.yml as arguments `python yaml_validator.py <schema.yaml> <input.yml>`.

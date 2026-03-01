"""
Author: Ben Janis
Date: 2026

This source file is part of an example system for MITRE's 2026 Embedded CTF
(eCTF). This code is being provided only for educational purposes for the 2026 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2026 The MITRE Corporation
"""

import argparse
import json
from pathlib import Path

from loguru import logger
import os


#this is a function which takes a list of integers as input and returns a bytes object
#the list of integers represents the groups that will be valid in this deployment
#the bytes object is the contents of the secrets file

def gen_secrets(groups: list[int]) -> bytes:
    """Generate the contents secrets file

    This will be passed to the Encoder, ectf26_design.gen_secrets,
    and the build process of the firmware

    NOTE: you should NOT write to secrets files within this function.
    All generated secrets must be contained in the returned bytes
    object.

    :param groups: List of permission groups that will be valid in this
        deployment.

    :returns: Contents of the secrets file
    """
    # Generate a cryptographically secure random 256-bit root secret
    #os.urandom() generates 32 bytes of random data and we convert it to a hex string here . 
    root_secret = os.urandom(32).hex()

    # Create the secrets object
    #this is a python dictionary which contains the groups and the root secret
    secrets = {
        "groups": groups,
        "root_secret": root_secret,
    }

    #secrets is a dict and we convert it to a json string so that it can be transported everywhere
    #then convert this json string to bytes , which is what we intend to return
    return json.dumps(secrets).encode()


#argparse library allows script to take arguments from the command line
#this is useful for testing and for allowing the user to specify the groups that will be valid in this deployment

#finally we will be giving something like 
# python gen_secrets.py --force ./my_file.txt 101 102
#this function below just takes care of parsing these arguments 
# the order of arguments is --force (optional) , secrets_file (required) , groups (required) 

def parse_args():
    """Define and parse the command line arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "groups",
        nargs="+",
        type=lambda x: int(x, 0),
        help="Supported group IDs",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets

    You will likely not have to change this function
    """
    # Parse the command line arguments using the function parse_args defined above
    args = parse_args()

    # Generate the secrets using the function gen_secrets defined above
    #the groups are taken from the terminal input of user and then sent to gen_secrets function
    secrets = gen_secrets(args.groups)

    # Print the generated secrets for your own debugging
    # Attackers will NOT have access to the output of this, but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    logger.debug(f"Generated secrets: {secrets}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)

    #Now the entire secrets {groups:[],root_secret:} is stored at the path args.secrets_file
    # For your own debugging. Feel free to remove
    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()

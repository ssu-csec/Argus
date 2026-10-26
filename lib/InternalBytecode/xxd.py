#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
This module exists so that a Windows build can have access to functionality
like xxd -i.
This script is intended to be compliant with both py2 and py3.
"""

import argparse
import sys
from os import path


                                                                          
BYTES_PER_LINE = 12
IS_PY3 = sys.version_info > (3, 0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    args = parser.parse_args()

                                                        
    if not path.exists(args.file):
        raise Exception('File "{}" doesn\'t exist'.format(args.file))

    with open(args.file, "rb") as f:
                                                                             
                                                   
        file_as_bytes = f.read()

                                                    
    lines = [
        file_as_bytes[i : i + BYTES_PER_LINE]
        for i in range(0, len(file_as_bytes), BYTES_PER_LINE)
    ]
                                                                   
                                                                
    print(
        ",\n".join(
            ", ".join("0x{:02x}".format(b if IS_PY3 else ord(b)) for b in l)
            for l in lines
        )
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Analyze saved inputs. Classification is a separate step."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from argus.cli import main

if __name__=='__main__':
    raise SystemExit(main(['analyze','--no-classify',*sys.argv[1:]]))

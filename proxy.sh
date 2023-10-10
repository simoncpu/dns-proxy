#!/bin/bash

which pip &> /dev/null
if [ $? -ne 0 ]; then
  echo "pip is not installed."
  echo "To install pip, first ensure you have python installed and then run:"
  echo "  curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py"
  echo "  python get-pip.py"
else
  sudo -u $SUDO_USER pip install -r requirements.txt
fi

if which python &> /dev/null; then
  PYTHON_CMD="python"
elif which python3 &> /dev/null; then
  PYTHON_CMD="python3"
else
  echo "Neither python nor python3 is installed."
  echo "Please install Python from https://www.python.org/downloads/ or via your package manager."
  exit 1
fi

echo "Using $PYTHON_CMD to run main.py"
$PYTHON_CMD main.py


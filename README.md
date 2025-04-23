# ROPBench

A testbed for evaluating defenses against return-oriented programming (ROP) style attacks in 64-bit systems

## Authors
Eric Zou (ezou626)

## Languages Used
- Python
- C

## Libraries Used
- ropper
- ROPgadget
- pwnlib

## How To Use

On the setup that you want to test, you will need to have both Python and a C compiler chain installed. 

Setup the virtual environment:
```bash
python -m venv venv
source venv/bin/activate # on linux
pip install -r requirements.txt
```

Then, run the test script. Sudp is required so the script can disable/enable certain protections like stack canaries, ASLR, etc.

```bash
sudo python -m main.py
```

Your results should be output in a file on the tested system called "results_[TIMESTAMP].csv"

## Files/Folders

## Attributions
### RISCV-ROP-Testbed

### RIPE

### RIPE64
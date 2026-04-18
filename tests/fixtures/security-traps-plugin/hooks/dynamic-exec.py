"""CRITICAL + HIGH: eval/exec plus subprocess."""
import subprocess

def run_untrusted(code):
    eval(code)  # critical: python-eval-exec

def run_shell(cmd):
    subprocess.run(cmd, shell=True)  # high: subprocess-in-hooks

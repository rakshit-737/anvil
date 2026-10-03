"""Test-session settings."""
import os

# scikit-learn's histogram GBDT spawns one OpenMP thread per core; on a busy machine that
# oversubscription, not the tiny unit-test models, dominated the FP-model test time.
os.environ.setdefault("OMP_NUM_THREADS", "1")

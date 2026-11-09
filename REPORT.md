# DES measurements

Actual measurements are saved in `benchmark-results/comparison/results.csv` and `environment.json`.

The saved experiment compares custom Python DES with PyCryptodome DES for BMP, PNG and JPEG files of approximately 3–5 KiB. Each configuration uses five runs, a 65,536-byte buffer and one or two processes where supported. Both ECB and CBC are measured for encryption and decryption; CBC encryption remains sequential.

On these small inputs, process startup and IPC dominate parallel measurements. These results do not establish the benefit of parallelism on large files. The full 1/10/101 MiB benchmark matrix has not been executed. The benchmark command in README can generate it.

CSV fields include median/min/max total and crypto times, median remaining overhead, throughput and parent-process peak RSS. Child-process memory is excluded. Environment metadata records the measurement machine and Python version. Input image generation happens outside the measured crypto operation.

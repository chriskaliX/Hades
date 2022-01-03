# Reconsidering CO-RE in eBPF

I was pretty confused about CO-RE with questions like the minimum kernel version we need for running or compiling or the impact of BTF in CO-RE both running and compiling. So this README is about to record the answers to those trivial issues that I came across.

# Q1: What is BTF?

BTF(BPF Type Format) is the metadata format that encodes the debug info related to the BPF program/map.
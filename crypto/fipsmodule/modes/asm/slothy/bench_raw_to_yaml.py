#!/usr/bin/env python3

import re
import yaml
import sys

def parse_benchmark_results(filename):
    results = {}

    with open(filename, 'r') as f:
        content = f.read()

    # Find all benchmark sections - updated pattern for new format
    benchmark_pattern = r'Benchmarking: ENC=(\d+), SZ=(\d+), VARIANT=([^\n]+)\n'
    matches = re.findall(benchmark_pattern, content)

    for enc, sz, variant in matches:
        # Find the section content
        section_start = content.find(f'Benchmarking: ENC={enc}, SZ={sz}, VARIANT={variant}')
        if section_start == -1:
            continue

        # Find next section or end
        next_section = content.find('Benchmarking:', section_start + 1)
        end_section = content.find('Getting variants for', section_start + 1)

        if next_section == -1 and end_section == -1:
            section_content = content[section_start:]
        elif next_section == -1:
            section_content = content[section_start:end_section]
        elif end_section == -1:
            section_content = content[section_start:next_section]
        else:
            section_content = content[section_start:min(next_section, end_section)]

        # Extract performance data - updated pattern for new format
        perf_lines = re.findall(r'Did \d+ EVP-AES-\d+-GCM (?:encrypt|decrypt) \((\d+) bytes\) operations in \d+us \([^)]+\): ([\d.]+) MB/s', section_content)

        if perf_lines:
            key = f"ENC{enc}_SZ{sz}_{variant}"
            results[key] = {
                'enc': int(enc),
                'sz': int(sz),
                'variant': variant,
                'performance': {}
            }

            for chunk_size, mbps in perf_lines:
                results[key]['performance'][int(chunk_size)] = {
                    'mbps': float(mbps)
                }

    return results

if __name__ == "__main__":
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    results = parse_benchmark_results(input_file)

    with open(output_file, 'w') as f:
        yaml.dump(results, f, default_flow_style=False, sort_keys=True)

    print(f"Converted {len(results)} benchmark results to {output_file}")

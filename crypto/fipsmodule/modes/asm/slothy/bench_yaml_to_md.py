#!/usr/bin/env python3
"""
Generate Markdown performance tables from AES-GCM benchmark YAML results.
"""

import yaml
import sys
from pathlib import Path

def load_yaml_data(yaml_file):
    """Load and parse the YAML benchmark data."""
    with open(yaml_file, 'r') as f:
        return yaml.safe_load(f)

def extract_performance_data(data):
    """Extract and organize performance data by configuration."""
    configs = {}
    
    for key, entry in data.items():
        if not key.startswith('ENC'):
            continue
            
        enc = entry['enc']
        sz = entry['sz']
        variant = entry['variant']
        performance = entry.get('performance', {})
        
        config_key = f"ENC{enc}_SZ{sz}"
        if config_key not in configs:
            configs[config_key] = {}
        
        # Only include variants with actual performance data
        if performance:
            configs[config_key][variant] = performance
    
    return configs

def get_chunk_sizes():
    """Return standard chunk sizes in order."""
    return [16, 128, 256, 512, 1350, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576]

def calculate_speedup(baseline_mbps, variant_mbps):
    """Calculate speedup relative to baseline."""
    if baseline_mbps == 0:
        return "-"
    return variant_mbps / baseline_mbps

def get_color_for_speedup(speedup):
    """Get HTML color styling based on speedup value using continuous spectrum."""
    if speedup == "-":
        return "color: #000000"  # Black for no data
    
    # Clamp speedup to reasonable range for color mapping
    clamped = max(0.5, min(speedup, 2.0))
    
    # Map speedup to 0-1 range: 0.5->0, 1.0->0.5, 2.0->1
    if clamped <= 1.0:
        # Red to yellow transition (0.5x to 1.0x)
        t = (clamped - 0.5) / 0.5
        r = 204  # Red component stays high
        g = int(t * 170)  # Green increases from 0 to 170
        b = 0
    else:
        # Yellow to green transition (1.0x to 2.0x)
        t = (clamped - 1.0) / 1.0
        r = int(204 * (1 - t))  # Red decreases from 204 to 0
        g = int(170 + t * 85)   # Green increases from 170 to 255
        b = 0
    
    return f"color: #{r:02x}{g:02x}{b:02x}"

def generate_markdown_table(config_name, config_data, chunk_sizes, max_chunk_size):
    """Generate Markdown table for a specific configuration."""
    # Filter chunk sizes based on max_chunk_size
    filtered_chunk_sizes = [size for size in chunk_sizes if size <= max_chunk_size]
    
    # Find baseline (awslc) performance
    baseline_perf = config_data.get('awslc', {})
    
    # Get all variants sorted (awslc first if present)
    variants = sorted(config_data.keys())
    if 'awslc' in variants:
        variants.remove('awslc')
        variants.insert(0, 'awslc')
    
    md = f'#### {config_name}\n\n'
    
    # Header row
    md += '| Variant |'
    for size in filtered_chunk_sizes:
        md += f' {size}B | |'
    md += '\n'
    
    # Separator row
    md += '|---------|'
    for _ in filtered_chunk_sizes:
        md += '------|------|'
    md += '\n'
    
    # Subheader row
    md += '| |'
    for _ in filtered_chunk_sizes:
        md += ' Mb/s | x |'
    md += '\n'
    
    # Data rows
    for variant in variants:
        perf_data = config_data[variant]
        
        # Style baseline variant differently
        if variant == 'awslc':
            md += f'| <span style="background-color: #f0f0f0; font-weight: bold">{variant}</span> |'
        else:
            md += f'| {variant} |'
        
        for size in filtered_chunk_sizes:
            if size in perf_data:
                mbps = perf_data[size]['mbps']
                if size in baseline_perf:
                    baseline_mbps = baseline_perf[size]['mbps']
                    speedup = calculate_speedup(baseline_mbps, mbps)
                    color = get_color_for_speedup(speedup)
                    speedup_text = f'<span style="{color}">{speedup:.2f}</span>'
                else:
                    speedup_text = "-"
                
                md += f' {mbps} | {speedup_text} |'
            else:
                md += ' - | - |'
        
        md += '\n'
    
    md += '\n'
    return md

def generate_complete_markdown(configs, chunk_sizes, max_chunk_size):
    """Generate complete Markdown document."""
    md = '### AES-GCM Performance: Optimization Potential\n\n'
    
    # Generate tables for each configuration
    config_order = ['ENC0_SZ128', 'ENC0_SZ192', 'ENC0_SZ256', 'ENC1_SZ128', 'ENC1_SZ192', 'ENC1_SZ256']
    config_titles = {
        'ENC0_SZ128': 'AES-GCM-128, Decrypt',
        'ENC0_SZ192': 'AES-GCM-192, Decrypt', 
        'ENC0_SZ256': 'AES-GCM-256, Decrypt',
        'ENC1_SZ128': 'AES-GCM-128, Encrypt',
        'ENC1_SZ192': 'AES-GCM-192, Encrypt',
        'ENC1_SZ256': 'AES-GCM-256, Encrypt'
    }
    
    for config_key in config_order:
        if config_key in configs:
            title = config_titles[config_key]
            md += generate_markdown_table(title, configs[config_key], chunk_sizes, max_chunk_size)
        else:
            print(f"Warning: Configuration {config_key} not found in data")
    
    return md

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 bench_yaml_to_md.py <input_yaml> <output_md> [max_chunk_size]")
        sys.exit(1)
    
    yaml_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2])
    max_chunk_size = int(sys.argv[3]) if len(sys.argv) > 3 else 32768  # Default 32K
    
    if not yaml_file.exists():
        print(f"Error: YAML file not found: {yaml_file}")
        sys.exit(1)
    
    print(f"Loading data from {yaml_file}")
    data = load_yaml_data(yaml_file)
    
    print("Extracting performance data...")
    configs = extract_performance_data(data)
    
    print(f"Found configurations: {list(configs.keys())}")
    print(f"Max chunk size: {max_chunk_size}B")
    
    chunk_sizes = get_chunk_sizes()
    
    print("Generating Markdown...")
    md = generate_complete_markdown(configs, chunk_sizes, max_chunk_size)
    
    print(f"Writing output to {output_file}")
    with open(output_file, 'w') as f:
        f.write(md)
    
    print("Done! Markdown performance tables generated.")

if __name__ == "__main__":
    main()

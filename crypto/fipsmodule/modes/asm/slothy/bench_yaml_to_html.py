#!/usr/bin/env python3
"""
Generate HTML performance tables from AES-GCM benchmark YAML results.
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
    return f"{variant_mbps / baseline_mbps:.2f}"

def generate_html_table(config_name, config_data, chunk_sizes, max_chunk_size):
    """Generate HTML table for a specific configuration."""
    # Filter chunk sizes based on max_chunk_size
    filtered_chunk_sizes = [size for size in chunk_sizes if size <= max_chunk_size]
    # Find baseline (awslc) performance
    baseline_perf = config_data.get('awslc', {})
    
    # Get all variants sorted (awslc first if present)
    variants = sorted(config_data.keys())
    if 'awslc' in variants:
        variants.remove('awslc')
        variants.insert(0, 'awslc')
    
    html = f'    <h4>{config_name}</h4>\n'
    html += '    <table>\n'
    
    # Header row 1 - chunk sizes
    html += '        <tr>\n'
    html += '            <th class="variant">Variant</th>\n'
    for size in filtered_chunk_sizes:
        size_str = f"{size}B"
        html += f'            <th>{size_str}</th><th></th>\n'
    html += '        </tr>\n'
    
    # Header row 2 - Mb/s and x labels
    html += '        <tr>\n'
    html += '            <th></th>\n'
    for _ in filtered_chunk_sizes:
        html += '            <th>Mb/s</th><th>x</th>\n'
    html += '        </tr>\n'
    
    # Data rows
    for variant in variants:
        perf_data = config_data[variant]
        html += '        <tr>\n'
        html += f'            <td class="variant">{variant}</td>\n'
        
        for size in filtered_chunk_sizes:
            if size in perf_data:
                mbps = perf_data[size]['mbps']
                if size in baseline_perf:
                    baseline_mbps = baseline_perf[size]['mbps']
                    speedup = calculate_speedup(baseline_mbps, mbps)
                    # Check if this is the baseline variant
                    if variant == 'awslc':
                        html += f'            <td class="mbps">{mbps}</td><td class="speedup baseline">{speedup}</td>\n'
                    else:
                        html += f'            <td class="mbps">{mbps}</td><td class="speedup">{speedup}</td>\n'
                else:
                    speedup = "-"
                    html += f'            <td class="mbps">{mbps}</td><td class="speedup">{speedup}</td>\n'
            else:
                html += '            <td class="mbps">-</td><td class="speedup">-</td>\n'
        
        html += '        </tr>\n'
    
    html += '    </table>\n\n'
    return html

def generate_complete_html(configs, chunk_sizes, max_chunk_size):
    """Generate complete HTML document."""
    html = '''<!DOCTYPE html>
<html>
<head>
    <title>AES-GCM Performance Analysis - Complete</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h3, h4 { color: #333; }
        h1 { font-size: 20px; }
        h2 { font-size: 16px; }
        table { border-collapse: collapse; margin: 20px 0; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 6px; text-align: center; font-size: 12px; }
        th { background-color: #f2f2f2; font-weight: bold; }
        .variant { text-align: left; font-weight: bold; min-width: 200px; }
        .mbps { background-color: #f9f9f9; }
        .speedup { font-weight: bold; }
    </style>
    <script>
        function getSpeedupColor(speedup) {
            if (speedup === '-') return '#ffffff';
            const value = parseFloat(speedup);
            if (isNaN(value)) return '#ffffff';
            
            const percent = (value - 1.0) * 100;
            
            let red, green, blue = 0;
            
            if (value < 0.95) {
                // Below -5%: Pure red
                red = 255;
                green = 0;
                blue = 0;
            } else if (value < 1.0) {
                // -5% to 0%: Red to Dark Orange
                const ratio = (value - 0.95) / 0.05; // 0 to 1
                red = 255;
                green = Math.round(140 * ratio); // From 0 (red) to 140 (dark orange)
                blue = 0;
            } else {
                const clampedPercent = Math.max(0, percent); // Remove the 25% cap
                
                if (clampedPercent <= 10) {
                    // 0% to 10%: Dark Orange to Yellow
                    red = 255;
                    green = Math.round(140 + 115 * (clampedPercent / 10)); // From 140 (dark orange) to 255 (yellow)
                    blue = 0;
                } else if (clampedPercent <= 25) {
                    // 10% to 25%: Yellow to Dark Green
                    red = Math.round(255 * (1 - (clampedPercent - 10) / 15));
                    green = Math.round(255 - 55 * ((clampedPercent - 10) / 15)); // Darker green (200 instead of 255)
                    blue = 0;
                } else {
                    // >25%: Stay at Dark Green
                    red = 0;
                    green = 200;
                    blue = 0;
                }
            }
            
            return `rgb(${red}, ${green}, ${blue})`;
        }
        
        function colorSpeedupCells() {
            const speedupCells = document.querySelectorAll('.speedup');
            speedupCells.forEach(cell => {
                const speedup = cell.textContent.trim();
                
                if (cell.classList.contains('baseline')) {
                    // Baseline cells are always grey
                    cell.style.backgroundColor = '#d3d3d3';
                    cell.style.color = '#000';
                } else {
                    // Regular speedup cells use the color gradient
                    cell.style.backgroundColor = getSpeedupColor(speedup);
                    cell.style.color = '#000';
                }
            });
        }
        
        window.onload = colorSpeedupCells;
    </script>
</head>
<body>
    <h3>AES-GCM Performance: Optimization Potential</h3>

'''
    
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
            html += generate_html_table(title, configs[config_key], chunk_sizes, max_chunk_size)
        else:
            print(f"Warning: Configuration {config_key} not found in data")
    
    html += '''</body>
</html>'''
    
    return html

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 generate_aes_gcm_tables.py <input_yaml> <output_html> [max_chunk_size]")
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
    
    print("Generating HTML...")
    html = generate_complete_html(configs, chunk_sizes, max_chunk_size)
    
    print(f"Writing output to {output_file}")
    with open(output_file, 'w') as f:
        f.write(html)
    
    print("Done! Open the HTML file in a browser to view the color-coded performance tables.")

if __name__ == "__main__":
    main()

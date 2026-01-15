#!/usr/bin/env python3
"""
Script to fix indentation errors in waf_engine.py
This script specifically fixes the over-indented try-except block
at lines 173-185 in the test_endpoint() function.
"""

import sys

def fix_waf_engine_indentation(file_path):
    """
    Fix the indentation issues in waf_engine.py
    The problem: Lines 173-185 have 8 spaces when try/except should have 4
    """
    
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    # Fix lines 172-185 (indices 172-186 in 0-based indexing)
    # Reduce indentation from 8 spaces to 4 for try/except lines
    # Reduce from 12 spaces to 8 for code inside try/except
    
    fixed_lines = []
    for i, line in enumerate(lines):
        # Lines 173-185 (indices 172-185)
        if 172 <= i <= 185:
            if line.strip():  # If line is not empty
                # Count leading spaces
                leading_spaces = len(line) - len(line.lstrip())
                
                # Try and except should be at 4 spaces
                if 'try:' in line or 'except' in line:
                    # Reduce from 8 to 4 spaces
                    fixed_lines.append(line[4:])
                # Content inside try/except should be at 8 spaces
                elif leading_spaces >= 12:
                    # Reduce from 12+ to 8
                    fixed_lines.append('    ' + line.lstrip())
                elif leading_spaces == 8:
                    # Already too much - reduce to 4
                    fixed_lines.append('    ' + line.lstrip())
                else:
                    fixed_lines.append(line)
            else:
                fixed_lines.append(line)
        else:
            fixed_lines.append(line)
    
    # Write the corrected content back
    with open(file_path, 'w') as f:
        f.writelines(fixed_lines)
    
    print(f"Fixed indentation in {file_path}")

if __name__ == '__main__':
    file_path = 'src/waf_engine.py'
    try:
        fix_waf_engine_indentation(file_path)
        print("✓ Indentation fix completed successfully")
        sys.exit(0)
    except Exception as e:
        print(f"✗ Error fixing indentation: {str(e)}")
        sys.exit(1)

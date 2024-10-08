# NSRLConvert-PY
NSRL (National Software Reference Library) RDS Hash Set Converter (Python Implementation)

# Author: David Haddad
# Breakpoint Forensics
# Full Credit to Chris Lees for original research and C-based tool @ https://askclees.com/2023/04/05/importing-nsrl-v3-hashsets-into-legacy-tools/ 
# Script: NSRLConvert-PY.py
# Date: 19-08-2024
# Vesion: 1.1

Changelog from Original NSRLConvert by Chris Lees:
  - Converted to Python 3 compliant code
  - Added support/detection for either Full or Minimal NSRL RDS Hash Set, with updated database parsing for each.
  - Memory management changes for improved support in lower RAM enviorments
  - Added progress meter and additional status messaging during conversion.
  - Added support for MD5 or SHA1 conversion from db file.
  - Added support for output to ProjectVIC style JSON as alternate to text file.

**Requirements:
**    
    Python 3.11 or newer
    
    Dependancy: UJSON Python Module
    
    pip install ujson
    
**    Usage:
**    
python script.py [input database] [output textfile] [hash_type] [output_format]
    
    hash_type is optional, but can be 'md5' (default) or 'sha1'
    output_format is optional, can be 'text' (default) or 'json'(ProjectVIC)

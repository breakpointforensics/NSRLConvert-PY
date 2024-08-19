import sqlite3
import time
import sys
import threading

# Author: David Haddad
# Breakpoint Forensics
# Full Credit to Chris Lees for original research and C-based tool @ https://askclees.com/2023/04/05/importing-nsrl-v3-hashsets-into-legacy-tools/ 
# Script: NSRLConvert-PY.py
# Date: 19-08-2024
# Version: 1.0

# SQLite PRAGMA statements to optimize performance
pragma = [
    "pragma journal_mode = WAL;",      # Use Write-Ahead Logging for better concurrency
    "pragma synchronous = normal;",    # Balance between safety and performance
    "pragma temp_store = memory;",     # Store temporary tables in memory to speed up processing
    "pragma mmap_size = 30000000000;"  # Set memory-mapped I/O to 30GB
]

def print_time(message):
    """Prints the current time with a custom message."""
    now = time.localtime()
    print(f"{message} {time.strftime('%Y-%m-%d %H:%M:%S', now)}")

def set_pragma(db):
    """Applies PRAGMA settings to optimize database performance."""
    cursor = db.cursor()
    for p in pragma:
        cursor.execute(p)
    cursor.close()

def print_usage():
    """Displays usage instructions for the script."""
    print("Usage:")
    print("\npython script.py [input database] [output textfile] [hash_type]")
    print("hash_type is optional, but can be 'md5' (default) or 'sha1'.")

def progress_meter(total_rows, processed_rows):
    """Displays a progress meter that updates every 5 seconds."""
    last_reported = 0
    while processed_rows[0] < total_rows:
        if processed_rows[0] > last_reported:
            percentage = (processed_rows[0] / total_rows) * 100
            print(f"Processed {processed_rows[0]} out of {total_rows} rows ({percentage:.2f}%)")
            last_reported = processed_rows[0]
        time.sleep(5)
    print(f"Processing complete: {processed_rows[0]} out of {total_rows} rows (100.00%)")

def get_view_name(cursor):
    """Determines whether to use the 'DISTINCT_HASH' or 'FILE' view."""
    cursor.execute("SELECT name FROM sqlite_master WHERE type='view';")
    views = [row[0] for row in cursor.fetchall()]
    
    if 'DISTINCT_HASH' in views:
        print('NSRL DB Style Detected: Minimal')
        return 'DISTINCT_HASH'
    elif 'FILE' in views:
        print('NSRL DB Style Detected: Full')
        return 'FILE'
    else:
        raise ValueError("Neither 'DISTINCT_HASH' nor 'FILE' view found in the database.")

def main(argv):
    if len(argv) < 3 or len(argv) > 4:
        print(f"{len(argv)-1} arguments given, 2 or 3 expected")
        print_usage()
        return

    # Determine the hash type: md5 (default) or sha1
    hash_type = argv[3] if len(argv) == 4 else 'md5'
    hash_type = hash_type.lower()
    if hash_type not in ['md5', 'sha1']:
        print("Invalid hash type specified. Use 'md5' or 'sha1'.")
        print_usage()
        return

    # Determine the column index based on the hash type
    hash_column = 2 if hash_type == 'md5' else 1
    print(f'Hash Format Selected: {hash_type}')

    print_time("Start Time is:")

    try:
        # Connect to the SQLite database
        db = sqlite3.connect(argv[1], uri=True)
        print("Opened database successfully")
    except sqlite3.Error as e:
        print(f"Can't open database: {e}")
        return

    # Apply performance optimizations
    set_pragma(db)

    try:
        cursor = db.cursor()
        
        # Determine the appropriate view to query
        view_name = get_view_name(cursor)
        print('Parsing Database...This can take a few minutes...')
        
        # Get the total number of rows for progress tracking
        cursor.execute(f"SELECT COUNT(*) FROM {view_name};")
        total_rows = cursor.fetchone()[0]
        print(f'Processing {total_rows} rows...')

        # Initialize a list to track the number of processed rows
        processed_rows = [0]

        # Start the progress meter in a separate thread
        progress_thread = threading.Thread(target=progress_meter, args=(total_rows, processed_rows))
        progress_thread.start()

        # Process the data in chunks to reduce memory usage
        chunk_size = 10000000  # Default chunk size of 10 million rows
        cursor.execute(f"SELECT * from {view_name};")

        with open(argv[2], "w") as md5:
            while True:
                rows = cursor.fetchmany(chunk_size)
                if not rows:
                    break
                for row in rows:
                    data = row[hash_column]  # Write the hash value to the output file
                    md5.write(data + "\n")
                    processed_rows[0] += 1

        # Wait for the progress meter thread to finish
        progress_thread.join()

        print_time("End Time is:")
    except sqlite3.Error as e:
        print(f"Failed to fetch data: {e}")
    except ValueError as ve:
        print(ve)
    finally:
        cursor.close()
        db.close()

if __name__ == "__main__":
    main(sys.argv)

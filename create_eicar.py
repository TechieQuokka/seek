#!/usr/bin/env python3
# Create EICAR test file with exact bytes

eicar_bytes = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

with open('eicar_test.txt', 'wb') as f:
    f.write(eicar_bytes)

print(f"Created EICAR file with {len(eicar_bytes)} bytes")
print(f"Content: {eicar_bytes}")
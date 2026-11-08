cd ~/ios_research

python3 << 'EOF'
import struct

def load_data_const(path):
    with open(path, 'rb') as f:
        return f.read()

data_2701 = load_data_const('data_const_2701.bin')
data_272 = load_data_const('data_const_272.bin')

print("=== Filtering for REAL vtable changes ===\n")

# The base shift is approximately 0x5000 for PAC pointers
# Real changes: pointers point to DIFFERENT functions, not just shifted

real_vtable_changes = []

for i in range(0, min(len(data_2701), len(data_272)) - 8, 8):
    val_2701 = struct.unpack('<Q', data_2701[i:i+8])[0]
    val_272 = struct.unpack('<Q', data_272[i:i+8])[0]
    
    if val_2701 == val_272:
        continue
    
    # Check if PAC-signed pointer (high bits 0x8011...)
    is_pac_2701 = (val_2701 >> 48) == 0x8011
    is_pac_272 = (val_272 >> 48) == 0x8011
    
    if is_pac_2701 and is_pac_272:
        # Extract lower 48 bits (actual address)
        addr_2701 = val_2701 & 0x0000FFFFFFFFFFFF
        addr_272 = val_272 & 0x0000FFFFFFFFFFFF
        
        # Calculate shift
        shift = addr_272 - addr_2701
        
        # If shift is NOT approximately 0x5000, this is interesting!
        if abs(shift - 0x5000) > 0x100:
            vmaddr = 0xfffffe0007e14000 + i
            real_vtable_changes.append({
                'offset': i,
                'vmaddr': vmaddr,
                'val_2701': val_2701,
                'val_272': val_272,
                'addr_2701': addr_2701,
                'addr_272': addr_272,
                'shift': shift
            })

print(f"Found {len(real_vtable_changes)} REAL vtable changes")

# Show first 20
print("\n=== First 20 REAL vtable changes ===")
for i, change in enumerate(real_vtable_changes[:20]):
    print(f"\n{i+1}. Offset 0x{change['offset']:x} (VM: 0x{change['vmaddr']:x})")
    print(f"   27.0.1: 0x{change['val_2701']:016x}")
    print(f"   27.2:   0x{change['val_272']:016x}")
    print(f"   Shift:  0x{change['shift']:x} (NOT ~0x5000)")
    print(f"   *** REAL CHANGE — DIFFERENT FUNCTION ***")

# Save for analysis
with open('real_vtable_changes.txt', 'w') as f:
    for change in real_vtable_changes:
        f.write(f"0x{change['vmaddr']:x} 0x{change['val_2701']:x} 0x{change['val_272']:x}\n")

print(f"\nSaved to real_vtable_changes.txt")
EOF

import os
import struct
import subprocess
import tempfile
import shutil
import argparse
import time
import threading
import sys
try:
    import lz4.frame
except ImportError:
    lz4 = None
try:
    import zstd
except ImportError:
    zstd = None

def timeout(timeout_duration, default=None):
    """Decorator for timeout using threading (Windows-compatible)."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            result = [default]
            def target():
                result[0] = func(*args, **kwargs)
            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(timeout_duration)
            if thread.is_alive():
                print(f"Warning: {func.__name__} timed out after {timeout_duration} seconds")
                return default
            return result[0]
        return wrapper
    return decorator

def align_size(size, page_size=4096):
    """Align size to the nearest page size."""
    return (size + page_size - 1) // page_size * page_size

@timeout(30, default=(None, None, None))
def scan_for_dtb(file_path, start_offset, file_size):
    """Scan boot.img for DTB/DHTB/FDT signatures with validation."""
    print(f"Scanning for DTB/DTBO from offset {start_offset}...")
    with open(file_path, 'rb') as f:
        f.seek(start_offset)
        chunk_size = 16384
        overlap = 512
        while f.tell() < file_size:
            chunk = f.read(chunk_size)
            for magic in [b'\xD0\x0D\xFE\xED', b'DTB', b'DHTB']:
                offset = chunk.find(magic)
                if offset != -1:
                    dtb_start = f.tell() - len(chunk) + offset
                    if dtb_start + 8 > file_size:
                        print(f"Warning: DTB at {dtb_start} exceeds file size {file_size}")
                        continue
                    f.seek(dtb_start)
                    header = f.read(8)
                    if len(header) < 8:
                        print(f"Warning: Incomplete DTB header at {dtb_start}")
                        continue
                    if magic == b'\xD0\x0D\xFE\xED':
                        try:
                            dtb_size = struct.unpack('>I', header[4:8])[0]
                            if not (1024 <= dtb_size <= min(1024*1024, file_size - dtb_start)):
                                print(f"Warning: Invalid DTB size {dtb_size} at {dtb_start}")
                                continue
                            return dtb_start, dtb_size, magic.hex()
                        except struct.error:
                            print(f"Warning: Failed to parse DTB size at {dtb_start}")
                            continue
                    else:
                        dtb_size = 1024
                        return dtb_start, dtb_size, magic.hex()
            f.seek(f.tell() - len(chunk) + overlap)
    return None, None, None

@timeout(30, default=(None, None))
def scan_for_avb(file_path, start_offset, file_size):
    """Scan boot.img for AVB signatures."""
    print(f"Scanning for AVB from offset {start_offset}...")
    with open(file_path, 'rb') as f:
        f.seek(start_offset)
        chunk_size = 16384
        while f.tell() < file_size:
            chunk = f.read(chunk_size)
            offset = chunk.find(b'AVB0')
            if offset != -1:
                avb_start = f.tell() - len(chunk) + offset
                f.seek(avb_start + 4)
                try:
                    avb_size = struct.unpack('<Q', f.read(8))[0]
                    if 64 <= avb_size <= file_size - avb_start:
                        f.seek(avb_start)
                        return avb_start, avb_size
                except struct.error:
                    continue
            f.seek(f.tell() - len(chunk) + 512)
    return None, None

@timeout(30, default=(None, None, None))
def scan_for_ramdisk(file_path, start_offset, file_size):
    """Scan boot.img for ramdisk signatures (gzip, cpio)."""
    print(f"Scanning for ramdisk from offset {start_offset}...")
    with open(file_path, 'rb') as f:
        f.seek(start_offset)
        chunk_size = 16384
        overlap = 512
        while f.tell() < file_size:
            chunk = f.read(chunk_size)
            for magic, compression in [
                (b'\x1f\x8b', 'gzip'),
                (b'\x04\x22\x4d\x18', 'lz4'),
                (b'\x28\xb5\x2f\xfd', 'zstd'),
                (b'070701', 'cpio'),
                (b'070702', 'cpio')
            ]:
                offset = chunk.find(magic)
                if offset != -1:
                    ramdisk_start = f.tell() - len(chunk) + offset
                    if ramdisk_start + 8 > file_size:
                        print(f"Warning: Ramdisk at {ramdisk_start} exceeds file size {file_size}")
                        continue
                    f.seek(ramdisk_start)
                    header = f.read(8)
                    if len(header) < 8:
                        print(f"Warning: Incomplete ramdisk header at {ramdisk_start}")
                        continue
                    f.seek(ramdisk_start)
                    remaining = f.read(file_size - ramdisk_start)
                    next_magic = file_size
                    for next_sig in [b'\x1f\x8b', b'\x04\x22\x4d\x18', b'\x28\xb5\x2f\xfd', b'070701', b'070702', b'ANDROID!']:
                        pos = remaining.find(next_sig)
                        if pos != -1 and pos > 0:
                            next_magic = min(next_magic, ramdisk_start + pos)
                    ramdisk_size = next_magic - ramdisk_start
                    if ramdisk_size < 1024 or ramdisk_size > file_size - ramdisk_start:
                        print(f"Warning: Invalid ramdisk size {ramdisk_size} at {ramdisk_start}")
                        continue
                    return ramdisk_start, ramdisk_size, compression
            f.seek(f.tell() - len(chunk) + overlap)
    return None, None, None

def safe_rename(src, dst, retries=5, delay=0.5):
    """Rename file with retries to handle file access errors."""
    for attempt in range(retries):
        try:
            os.rename(src, dst)
            return True
        except OSError as e:
            if attempt < retries - 1:
                print(f"Warning: Failed to rename {src} to {dst}: {e}. Retrying in {delay}s...")
                time.sleep(delay)
            else:
                print(f"Error: Failed to rename {src} to {dst} after {retries} attempts: {e}")
                return False
    return False

@timeout(300, default={})
def parse_boot_image(boot_img, output_dir, skip_ramdisk=False, skip_dtb=False, skip_avb=True, force=False, debug_cpio=False):
    """Parse boot.img and extract all components."""
    print(f"Checking write access to {output_dir}")
    try:
        os.makedirs(output_dir, exist_ok=True)
        test_file = os.path.join(output_dir, 'test.txt')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
    except OSError as e:
        print(f"Error: Cannot write to {output_dir}: {e}")
        return {}

    file_size = os.path.getsize(boot_img)
    print(f"boot.img size: {file_size} bytes")
    if file_size < 160:
        print(f"Error: Invalid boot image: file too small, got {file_size} bytes")
        return {}

    try:
        with open(boot_img, 'rb') as f:
            header = f.read(1664)
            print(f"Header size: {len(header)} bytes")
            print(f"First 64 bytes of header: {header[:64].hex()}")

            magic = header[:8]
            if magic != b'ANDROID!' and not force:
                print(f"Error: Invalid boot image: bad magic {magic}")
                return {}

            try:
                kernel_size = struct.unpack('<I', header[8:12])[0]
                kernel_addr = struct.unpack('<I', header[12:16])[0]
                ramdisk_size = struct.unpack('<I', header[16:20])[0]
                ramdisk_addr = struct.unpack('<I', header[20:24])[0]
                second_size = struct.unpack('<I', header[24:28])[0]
                second_addr = struct.unpack('<I', header[28:32])[0]
                tags_addr = struct.unpack('<I', header[32:36])[0]
                page_size = struct.unpack('<I', header[36:40])[0]
                header_version = struct.unpack('<I', header[40:44])[0]
                extra_field = struct.unpack('<I', header[44:48])[0]
                os_version = header[48:64]
            except struct.error as e:
                print(f"Warning: Failed to parse header: {e}")
                if not force:
                    return {}
                kernel_size = ramdisk_size = second_size = page_size = header_version = extra_field = 0
                kernel_addr = ramdisk_addr = second_addr = tags_addr = 0
                os_version = b''

            if header_version > 4:
                print(f"Warning: Unsupported header version: {header_version}, treating as v0")
                header_version = 0
                dtb_size = extra_field
                dtb_addr = 0
            else:
                dtb_size = 0
                dtb_addr = 0

            recovery_dtbo_size = 0
            recovery_dtbo_offset = 0
            header_size = 0
            vendor_ramdisk_size = 0
            dtb_size_v4 = 0
            dtb_offset_v4 = 0
            if header_version >= 3 and len(header) >= 80:
                try:
                    recovery_dtbo_size = struct.unpack('<I', header[64:68])[0]
                    recovery_dtbo_offset = struct.unpack('<Q', header[68:76])[0]
                    header_size = struct.unpack('<I', header[76:80])[0]
                except struct.error:
                    print("Warning: Failed to parse v3/v4 fields")
            if header_version >= 4 and len(header) >= 96:
                try:
                    vendor_ramdisk_size = struct.unpack('<I', header[80:84])[0]
                    dtb_size_v4 = struct.unpack('<I', header[84:88])[0]
                    dtb_offset_v4 = struct.unpack('<Q', header[88:96])[0]
                except struct.error:
                    print("Warning: Failed to parse v4 fields")

            valid_page_sizes = [2048, 4096, 8192, 16384]
            if page_size not in valid_page_sizes:
                print(f"Warning: Invalid page_size {page_size}, assuming 4096")
                page_size = 4096

            cmdline = header[64:576].decode('latin-1', errors='ignore').rstrip('\x00') if len(header) >= 576 else ''
            id_ = header[576:608] if len(header) >= 608 else b''
            extra_cmdline = header[608:1104] if len(header) >= 1104 else b''
            board_name = header[1104:1120].decode('latin-1', errors='ignore').rstrip('\x00') if len(header) >= 1120 else ''

            print(f"Parsed Header: kernel_size={kernel_size}, ramdisk_size={ramdisk_size}, second_size={second_size}, "
                  f"dtb_size={dtb_size}, recovery_dtbo_size={recovery_dtbo_size}, vendor_ramdisk_size={vendor_ramdisk_size}, "
                  f"page_size={page_size}, header_version={header_version}, board_name={board_name}")

            dtb_offset = dtb_offset_v4 if dtb_size_v4 else dtb_addr
            dtb_magic = None
            if not skip_dtb and dtb_size == 0 and dtb_size_v4 == 0:
                dtb_offset, dtb_size, dtb_magic = scan_for_dtb(boot_img, page_size, file_size)
                if dtb_offset is not None:
                    print(f"Found DTB/DTBO at offset {dtb_offset}, size {dtb_size}, magic {dtb_magic}")

            avb_offset, avb_size = (None, None) if skip_avb else scan_for_avb(boot_img, page_size, file_size)
            if avb_offset is not None:
                print(f"Found AVB signature at offset {avb_offset}, size {avb_size}")

            ramdisk_offset = align_size(page_size + kernel_size, page_size) if ramdisk_size else None
            ramdisk_compression = 'unknown'
            if not skip_ramdisk and ramdisk_size == 0:
                print("Warning: ramdisk_size is 0, scanning for ramdisk signatures...")
                ramdisk_offset, ramdisk_size, ramdisk_compression = scan_for_ramdisk(boot_img, page_size, file_size)
                if ramdisk_offset is not None:
                    print(f"Found ramdisk at offset {ramdisk_offset}, size {ramdisk_size}, compression {ramdisk_compression}")
                else:
                    print("No ramdisk found after scanning")

            kernel_offset = page_size
            second_offset = align_size(ramdisk_offset + ramdisk_size, page_size) if ramdisk_size else align_size(kernel_offset + kernel_size, page_size)
            dtb_offset = align_size(second_offset + second_size, page_size) if dtb_size and dtb_offset is None else dtb_offset
            recovery_dtbo_offset = recovery_dtbo_offset if recovery_dtbo_size else 0
            vendor_ramdisk_offset = align_size(dtb_offset + (dtb_size or 0), page_size) if vendor_ramdisk_size else 0

            for name, offset, size in [
                ('kernel', kernel_offset, kernel_size),
                ('ramdisk', ramdisk_offset, ramdisk_size),
                ('second', second_offset, second_size),
                ('dtb', dtb_offset, dtb_size),
                ('recovery_dtbo', recovery_dtbo_offset, recovery_dtbo_size),
                ('vendor_ramdisk', vendor_ramdisk_offset, vendor_ramdisk_size)
            ]:
                if size and offset and offset + size > file_size:
                    print(f"Warning: Invalid {name} offset/size: offset={offset}, size={size}, file_size={file_size}")

            @timeout(30, default=False)
            def extract_component(name, offset, size, output_path, temp_path=None):
                print(f"Extracting {name}...")
                if size and offset:
                    f.seek(offset)
                    data = f.read(size)
                    if len(data) != size:
                        print(f"Warning: Read {len(data)} bytes for {name}, expected {size}")
                        return False
                    try:
                        target_path = temp_path if temp_path else output_path
                        with open(target_path, 'wb') as out:
                            out.write(data)
                        if temp_path and not safe_rename(temp_path, output_path):
                            print(f"Warning: Using temporary file {temp_path} for {name} due to rename failure")
                            return True
                        print(f"Extracted {name} to: {output_path}")
                        return True
                    except OSError as e:
                        print(f"Warning: Failed to write {name}: {e}")
                        return False
                return False

            if kernel_size:
                kernel_path = os.path.join(output_dir, 'kernel')
                extract_component('kernel', kernel_offset, kernel_size, kernel_path)

            ramdisk_path = None
            if ramdisk_size and ramdisk_offset and not skip_ramdisk:
                extension_map = {'gzip': 'gz', 'lz4': 'lz4', 'zstd': 'zst', 'cpio': 'cpio'}
                ramdisk_ext = extension_map.get(ramdisk_compression, 'cpio')
                ramdisk_path = os.path.join(output_dir, f'ramdisk.cpio.{ramdisk_ext}')
                temp_ramdisk_path = os.path.join(output_dir, f'temp_ramdisk_{os.getpid()}.bin')
                if extract_component('ramdisk', ramdisk_offset, ramdisk_size, ramdisk_path, temp_path=temp_ramdisk_path):
                    try:
                        with open(ramdisk_path, 'rb') as rf:
                            magic = rf.read(4)
                        if magic.startswith(b'\x1f\x8b'):
                            ramdisk_compression = 'gzip'
                            if not ramdisk_path.endswith('.gz'):
                                new_path = os.path.join(output_dir, 'ramdisk.cpio.gz')
                                if safe_rename(ramdisk_path, new_path):
                                    ramdisk_path = new_path
                                else:
                                    print(f"Warning: Continuing with {ramdisk_path}")
                        elif magic == b'\x04\x22\x4d\x18' and lz4:
                            ramdisk_compression = 'lz4'
                            if not ramdisk_path.endswith('.lz4'):
                                new_path = os.path.join(output_dir, 'ramdisk.cpio.lz4')
                                if safe_rename(ramdisk_path, new_path):
                                    ramdisk_path = new_path
                                else:
                                    print(f"Warning: Continuing with {ramdisk_path}")
                        elif magic.startswith(b'\x28\xb5\x2f\xfd') and zstd:
                            ramdisk_compression = 'zstd'
                            if not ramdisk_path.endswith('.zst'):
                                new_path = os.path.join(output_dir, 'ramdisk.cpio.zst')
                                if safe_rename(ramdisk_path, new_path):
                                    ramdisk_path = new_path
                                else:
                                    print(f"Warning: Continuing with {ramdisk_path}")
                        else:
                            ramdisk_compression = 'cpio'
                            if not ramdisk_path.endswith('.cpio'):
                                new_path = os.path.join(output_dir, 'ramdisk.cpio')
                                if safe_rename(ramdisk_path, new_path):
                                    ramdisk_path = new_path
                                else:
                                    print(f"Warning: Continuing with {ramdisk_path}")
                        print(f"Ramdisk detected as {ramdisk_compression}-compressed")
                    except OSError as e:
                        print(f"Warning: Failed to verify ramdisk compression: {e}")
                    finally:
                        if os.path.exists(temp_ramdisk_path):
                            try:
                                os.remove(temp_ramdisk_path)
                            except OSError:
                                pass

            if second_size and second_offset:
                second_path = os.path.join(output_dir, 'second')
                extract_component('second', second_offset, second_size, second_path)

            if dtb_size and dtb_offset and not skip_dtb:
                dtb_path = os.path.join(output_dir, 'dtb')
                extract_component('dtb', dtb_offset, dtb_size, dtb_path)

            if recovery_dtbo_size and recovery_dtbo_offset:
                recovery_dtbo_path = os.path.join(output_dir, 'recovery_dtbo')
                extract_component('recovery_dtbo', recovery_dtbo_offset, recovery_dtbo_size, recovery_dtbo_path)

            vendor_ramdisk_path = None
            if vendor_ramdisk_size and vendor_ramdisk_offset and not skip_ramdisk:
                vendor_ramdisk_path = os.path.join(output_dir, 'vendor_ramdisk.cpio.gz')
                temp_vendor_path = os.path.join(output_dir, f'temp_vendor_ramdisk_{os.getpid()}.bin')
                if extract_component('vendor_ramdisk', vendor_ramdisk_offset, vendor_ramdisk_size, vendor_ramdisk_path, temp_path=temp_vendor_path):
                    try:
                        with open(vendor_ramdisk_path, 'rb') as rf:
                            magic = rf.read(4)
                        if magic == b'\x04\x22\x4d\x18' and lz4:
                            print("Vendor ramdisk is LZ4-compressed")
                            new_path = os.path.join(output_dir, 'vendor_ramdisk.cpio.lz4')
                            if safe_rename(vendor_ramdisk_path, new_path):
                                vendor_ramdisk_path = new_path
                        elif magic.startswith(b'\x28\xb5\x2f\xfd') and zstd:
                            print("Vendor ramdisk is ZSTD-compressed")
                            new_path = os.path.join(output_dir, 'vendor_ramdisk.cpio.zst')
                            if safe_rename(vendor_ramdisk_path, new_path):
                                vendor_ramdisk_path = new_path
                    except OSError as e:
                        print(f"Warning: Failed to verify vendor ramdisk compression: {e}")
                    finally:
                        if os.path.exists(temp_vendor_path):
                            try:
                                os.remove(temp_vendor_path)
                            except OSError:
                                pass

            if avb_offset and avb_size and not skip_avb:
                avb_path = os.path.join(output_dir, 'avb_signature.bin')
                extract_component('avb_signature', avb_offset, avb_size, avb_path)

            ramdisk_dir = None
            if ramdisk_path and os.path.exists(ramdisk_path) and not skip_ramdisk:
                ramdisk_dir = os.path.join(output_dir, 'ramdisk')
                try:
                    extract_ramdisk(ramdisk_path, ramdisk_dir, debug_cpio=debug_cpio)
                except Exception as e:
                    print(f"Warning: Failed to extract ramdisk contents: {e}")

            vendor_ramdisk_dir = None
            if vendor_ramdisk_path and os.path.exists(vendor_ramdisk_path) and not skip_ramdisk:
                vendor_ramdisk_dir = os.path.join(output_dir, 'vendor_ramdisk')
                try:
                    extract_ramdisk(vendor_ramdisk_path, vendor_ramdisk_dir, debug_cpio=debug_cpio)
                except Exception as e:
                    print(f"Warning: Failed to extract vendor ramdisk contents: {e}")

            print("Extracting metadata...")
            bootimg_info_path = os.path.join(output_dir, 'bootimg_info.txt')
            metadata_written = False
            try:
                with open(bootimg_info_path, 'w', encoding='utf-8') as out:
                    out.write(f"Magic: {magic.hex()}\n")
                    out.write(f"Kernel Size: {kernel_size}\n")
                    out.write(f"Ramdisk Size: {ramdisk_size}\n")
                    out.write(f"Second Size: {second_size}\n")
                    out.write(f"DTB Size: {dtb_size}\n")
                    out.write(f"Recovery DTBO Size: {recovery_dtbo_size}\n")
                    out.write(f"Vendor Ramdisk Size: {vendor_ramdisk_size}\n")
                    out.write(f"Page Size: {page_size}\n")
                    out.write(f"Header Version: {header_version}\n")
                    out.write(f"Board Name: {board_name}\n")
                    out.write(f"Command Line: {cmdline}\n")
                    out.write(f"OS Version: {os_version.hex()}\n")
                metadata_written = True
            except OSError as e:
                print(f"Warning: Failed to write bootimg_info: {e}")

            cmdline_path = os.path.join(output_dir, 'cmdline.txt')
            try:
                with open(cmdline_path, 'w', encoding='utf-8') as out:
                    out.write(cmdline)
            except OSError as e:
                print(f"Warning: Failed to write cmdline: {e}")

            id_path = os.path.join(output_dir, 'id.bin')
            try:
                with open(id_path, 'wb') as out:
                    out.write(id_)
            except OSError as e:
                print(f"Warning: Failed to write id: {e}")

            if extra_cmdline:
                extra_cmdline_path = os.path.join(output_dir, 'extra_cmdline.txt')
                try:
                    with open(extra_cmdline_path, 'wb') as out:
                        out.write(extra_cmdline)
                    if metadata_written:
                        print(f"Extracted metadata to: {bootimg_info_path}, {cmdline_path}, {id_path}, {extra_cmdline_path}")
                    else:
                        print(f"Extracted partial metadata to: {cmdline_path}, {id_path}, {extra_cmdline_path}")
                except OSError as e:
                    print(f"Warning: Failed to write extra_cmdline: {e}")
            else:
                if metadata_written:
                    print(f"Extracted metadata to: {bootimg_info_path}, {cmdline_path}, {id_path}")
                else:
                    print(f"Extracted partial metadata to: {cmdline_path}, {id_path}")

            return {
                'kernel_size': kernel_size,
                'ramdisk_size': ramdisk_size,
                'second_size': second_size,
                'dtb_size': dtb_size,
                'recovery_dtbo_size': recovery_dtbo_size,
                'vendor_ramdisk_size': vendor_ramdisk_size,
                'page_size': page_size,
                'kernel_addr': kernel_addr,
                'ramdisk_addr': ramdisk_addr,
                'second_addr': second_addr,
                'dtb_addr': dtb_addr,
                'tags_addr': tags_addr,
                'os_version': os_version,
                'name': os_version,
                'cmdline': cmdline.encode('latin-1', errors='ignore'),
                'id': id_,
                'extra_cmdline': extra_cmdline,
                'board_name': board_name.encode('latin-1', errors='ignore'),
                'ramdisk_path': ramdisk_path,
                'vendor_ramdisk_path': vendor_ramdisk_path,
                'ramdisk_dir': ramdisk_dir,
                'vendor_ramdisk_dir': vendor_ramdisk_dir,
                'ramdisk_compression': ramdisk_compression
            }
    except Exception as e:
        print(f"Error in parse_boot_image: {e}")
        return {}

@timeout(300, default=None)
def extract_ramdisk(ramdisk_file, output_dir, debug_cpio=False):
    """Extract ramdisk (gzip, LZ4, ZSTD, or raw) using 7-Zip."""
    print(f"Extracting ramdisk: {ramdisk_file}")
    os.makedirs(output_dir, exist_ok=True)

    temp_cpio = os.path.join(os.path.dirname(ramdisk_file), 'temp.cpio')
    debug_cpio_path = os.path.join(os.path.dirname(ramdisk_file), 'saved_temp.cpio')
    seven_zip_path = r"C:\Users\Administrator\Desktop\un\Zip\7z.exe"

    if not os.path.exists(seven_zip_path):
        print(f"Error: 7-Zip not found at {seven_zip_path}")
        return

    try:
        with open(ramdisk_file, 'rb') as f:
            magic = f.read(4)
            f.seek(0)
            if magic.startswith(b'\x1f\x8b'):
                print("Decompressing gzip ramdisk with 7-Zip...")
                cmd = [seven_zip_path, "x", ramdisk_file, f"-o{os.path.dirname(temp_cpio)}", "-y", "ramdisk.cpio"]
                print(f"Running: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    print(f"Error: 7-Zip decompression failed: {result.stderr}")
                    return
                extracted_cpio = os.path.join(os.path.dirname(temp_cpio), 'ramdisk.cpio')
                if os.path.exists(extracted_cpio):
                    if safe_rename(extracted_cpio, temp_cpio):
                        print(f"Decompressed to {temp_cpio}")
                    else:
                        print(f"Warning: Using {extracted_cpio} due to rename failure")
                        temp_cpio = extracted_cpio
                else:
                    print(f"Error: Expected {extracted_cpio} not found after 7-Zip decompression")
                    return
            elif magic == b'\x04\x22\x4d\x18' and lz4:
                print("Decompressing LZ4 ramdisk...")
                with lz4.frame.open(ramdisk_file, 'rb') as lz, open(temp_cpio, 'wb') as out:
                    chunk_size = 1024 * 1024
                    while True:
                        chunk = lz.read(chunk_size)
                        if not chunk:
                            break
                        out.write(chunk)
            elif magic.startswith(b'\x28\xb5\x2f\xfd') and zstd:
                print("Decompressing ZSTD ramdisk...")
                with open(ramdisk_file, 'rb') as rf, open(temp_cpio, 'wb') as out:
                    decompressor = zstd.ZstdDecompressor()
                    out.write(decompressor.decompress(rf.read()))
            else:
                print("Warning: Unknown ramdisk compression, treating as raw cpio")
                temp_cpio = ramdisk_file

        if temp_cpio != ramdisk_file and os.path.exists(temp_cpio):
            print(f"Extracting cpio to {output_dir} with 7-Zip...")
            cmd = [seven_zip_path, "x", temp_cpio, f"-o{output_dir}", "-y"]
            print(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Error: 7-Zip cpio extraction failed: {result.stderr}")
            else:
                print(f"Extracted cpio to {output_dir}")

            shutil.copy(temp_cpio, debug_cpio_path)
            print(f"Saved temp.cpio to: {debug_cpio_path}")
            try:
                os.remove(temp_cpio)
            except OSError as e:
                print(f"Warning: Failed to remove {temp_cpio}: {e}")

            if debug_cpio:
                debug_file = os.path.join(os.path.dirname(temp_cpio), 'cpio_debug.log')
                print(f"Writing cpio debug log to: {debug_file}")
                try:
                    with open(debug_file, 'w', encoding='utf-8') as df:
                        df.write(f"Extracted files from {temp_cpio}:\n")
                        file_count = 0
                        for root, dirs, files in os.walk(output_dir):
                            for file in files:
                                rel_path = os.path.relpath(os.path.join(root, file), output_dir)
                                df.write(f"{rel_path}\n")
                                file_count += 1
                        df.write(f"\nTotal files extracted: {file_count}\n")
                except OSError as e:
                    print(f"Warning: Failed to write cpio debug log: {e}")

    except Exception as e:
        print(f"Failed to extract ramdisk: {e}")
        if temp_cpio != ramdisk_file and os.path.exists(temp_cpio):
            shutil.copy(temp_cpio, debug_cpio_path)
            print(f"Saved temp.cpio to: {debug_cpio_path}")
            try:
                os.remove(temp_cpio)
            except OSError:
                pass

@timeout(300, default=None)
def create_cpio(input_dir, cpio_file):
    """Create cpio archive from a directory using 7-Zip."""
    print(f"Creating cpio archive: {cpio_file}")
    seven_zip_path = r"C:\Users\Administrator\Desktop\un\Zip\7z.exe"

    if not os.path.exists(seven_zip_path):
        print(f"Error: 7-Zip not found at {seven_zip_path}")
        return

    temp_dir = tempfile.mkdtemp()
    temp_cpio = os.path.join(temp_dir, 'ramdisk.cpio')

    try:
        cmd = [seven_zip_path, "a", "-ttar", temp_cpio, os.path.join(input_dir, "*")]
        print(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error: 7-Zip cpio creation failed: {result.stderr}")
            return

        if os.path.exists(temp_cpio):
            shutil.move(temp_cpio, cpio_file)
            print(f"Created cpio archive: {cpio_file}")
        else:
            print(f"Error: Expected {temp_cpio} not found after 7-Zip cpio creation")

    except Exception as e:
        print(f"Error in cpio creation: {e}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

@timeout(300, default=None)
def repack_ramdisk(ramdisk_dir, output_cpio, compression='gzip'):
    """Rebuild ramdisk with specified compression using 7-Zip."""
    print(f"Repacking ramdisk to: {output_cpio}")
    seven_zip_path = r"C:\Users\Administrator\Desktop\un\Zip\7z.exe"

    if not os.path.exists(seven_zip_path):
        print(f"Error: 7-Zip not found at {seven_zip_path}")
        return

    temp_cpio = output_cpio + '.temp'

    create_cpio(ramdisk_dir, temp_cpio)

    if not os.path.exists(temp_cpio):
        print(f"Error: Failed to create temporary cpio {temp_cpio}")
        return

    try:
        if compression == 'gzip':
            cmd = [seven_zip_path, "a", "-tgzip", output_cpio, temp_cpio]
            print(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Error: 7-Zip gzip compression failed: {result.stderr}")
            else:
                print(f"Compressed to {output_cpio}")
        elif compression == 'lz4' and lz4:
            with lz4.frame.open(output_cpio, 'wb') as lz:
                with open(temp_cpio, 'rb') as f:
                    lz.write(f.read())
        elif compression == 'zstd' and zstd:
            with open(temp_cpio, 'rb') as rf, open(output_cpio, 'wb') as out:
                compressor = zstd.ZstdCompressor()
                out.write(compressor.compress(rf.read()))
        else:
            print(f"Warning: Compression {compression} not available, saving as raw")
            shutil.move(temp_cpio, output_cpio)
    except Exception as e:
        print(f"Error in ramdisk repacking: {e}")
    finally:
        if os.path.exists(temp_cpio):
            try:
                os.remove(temp_cpio)
            except OSError:
                pass

@timeout(300, default=None)
def repack_boot_image(header_info, components_dir, output_boot_img):
    """Repack boot image from components."""
    page_size = header_info['page_size']
    kernel_path = os.path.join(components_dir, 'kernel')
    ramdisk_path = header_info.get('ramdisk_path', os.path.join(components_dir, 'ramdisk.cpio.gz'))
    second_path = os.path.join(components_dir, 'second')
    dtb_path = os.path.join(components_dir, 'dtb')
    recovery_dtbo_path = os.path.join(components_dir, 'recovery_dtbo')
    vendor_ramdisk_path = header_info.get('vendor_ramdisk_path', os.path.join(components_dir, 'vendor_ramdisk.cpio.gz'))

    if os.path.exists(kernel_path):
        with open(kernel_path, 'rb') as f:
            kernel_data = f.read()
        kernel_size = len(kernel_data)
    else:
        kernel_data = b''
        kernel_size = 0

    if os.path.exists(ramdisk_path):
        with open(ramdisk_path, 'rb') as f:
            ramdisk_data = f.read()
        ramdisk_size = len(ramdisk_data)
    else:
        ramdisk_data = b''
        ramdisk_size = 0

    second_size = 0
    second_data = b''
    if os.path.exists(second_path):
        with open(second_path, 'rb') as f:
            second_data = f.read()
        second_size = len(second_data)

    dtb_size = 0
    dtb_data = b''
    if os.path.exists(dtb_path):
        with open(dtb_path, 'rb') as f:
            dtb_data = f.read()
        dtb_size = len(dtb_data)

    recovery_dtbo_size = 0
    recovery_dtbo_data = b''
    if os.path.exists(recovery_dtbo_path):
        with open(recovery_dtbo_path, 'rb') as f:
            recovery_dtbo_data = f.read()
        recovery_dtbo_size = len(recovery_dtbo_data)

    vendor_ramdisk_size = 0
    vendor_ramdisk_data = b''
    if os.path.exists(vendor_ramdisk_path):
        with open(vendor_ramdisk_path, 'rb') as f:
            vendor_ramdisk_data = f.read()
        vendor_ramdisk_size = len(vendor_ramdisk_data)

    kernel_offset = page_size
    ramdisk_offset = align_size(kernel_offset + kernel_size, page_size)
    second_offset = align_size(ramdisk_offset + ramdisk_size, page_size)
    dtb_offset = align_size(second_offset + second_size, page_size)
    recovery_dtbo_offset = align_size(dtb_offset + dtb_size, page_size) if recovery_dtbo_size else 0
    vendor_ramdisk_offset = align_size(recovery_dtbo_offset + recovery_dtbo_size, page_size) if vendor_ramdisk_size else 0

    header = struct.pack(
        '<8sIIIIIIIII16s512s32s496s16s',
        b'ANDROID!',
        kernel_size,
        header_info['kernel_addr'],
        ramdisk_size,
        header_info['ramdisk_addr'],
        second_size,
        header_info['second_addr'],
        header_info['tags_addr'],
        page_size,
        header_info.get('recovery_dtbo_size', 0),
        header_info.get('dtb_addr', 0),
        header_info['os_version'],
        header_info['name'],
        header_info['cmdline'],
        header_info['id'],
        header_info['extra_cmdline'],
        header_info.get('board_name', b'')
    )

    with open(output_boot_img, 'wb') as f:
        f.write(header)
        f.write(b'\x00' * (page_size - len(header)))
        if kernel_size:
            f.write(kernel_data)
        if ramdisk_size:
            f.write(b'\x00' * (ramdisk_offset - f.tell()))
            f.write(ramdisk_data)
        if second_size:
            f.write(b'\x00' * (second_offset - f.tell()))
            f.write(second_data)
        if dtb_size:
            f.write(b'\x00' * (dtb_offset - f.tell()))
            f.write(dtb_data)
        if recovery_dtbo_size:
            f.write(b'\x00' * (recovery_dtbo_offset - f.tell()))
            f.write(recovery_dtbo_data)
        if vendor_ramdisk_size:
            f.write(b'\x00' * (vendor_ramdisk_offset - f.tell()))
            f.write(vendor_ramdisk_data)

def main():
    """Main function to handle different operations."""
    parser = argparse.ArgumentParser(description="Unpack, modify, or repack Android boot images.")
    parser.add_argument("operation", choices=["extract", "repack", "full"], help="Operation to perform: extract, repack, or full")
    parser.add_argument("boot_img", help="Path to the boot image file")
    parser.add_argument("--output-dir", default="output", help="Directory to store extracted files (default: ./output)")
    parser.add_argument("--skip-ramdisk", action="store_true", help="Skip ramdisk extraction")
    parser.add_argument("--skip-dtb", action="store_true", help="Skip DTB/DTBO extraction")
    parser.add_argument("--skip-avb", action="store_true", help="Skip AVB signature scanning", default=True)
    parser.add_argument("--force", action="store_true", help="Force extraction despite errors")
    parser.add_argument("--debug-cpio", action="store_true", help="Enable cpio debugging to log extracted files")

    args = parser.parse_args()

    print(f"Running unpack.py from: {os.path.abspath(__file__)}")
    output_dir = os.path.abspath(args.output_dir)
    print(f"Using output directory: {output_dir}")

    try:
        if args.operation in ["extract", "full"]:
            header_info = parse_boot_image(
                args.boot_img,
                output_dir,
                skip_ramdisk=args.skip_ramdisk,
                skip_dtb=args.skip_dtb,
                skip_avb=args.skip_avb,
                force=args.force,
                debug_cpio=args.debug_cpio
            )
            if not header_info:
                print("Warning: Failed to parse boot image, some components may be missing")
            else:
                print(f"Extraction complete. Files are in: {output_dir}")

            if args.operation == "extract":
                return

            ramdisk_dir = header_info.get('ramdisk_dir')
            if ramdisk_dir and os.path.exists(ramdisk_dir):
                print(f"Ramdisk directory ready for modification: {ramdisk_dir}")
                with open(os.path.join(ramdisk_dir, 'test.txt'), 'w') as f:
                    f.write("This is a test file")

                ramdisk_path = header_info.get('ramdisk_path')
                if ramdisk_path:
                    compression = header_info.get('ramdisk_compression', 'gzip')
                    repack_ramdisk(ramdisk_dir, ramdisk_path, compression)

                vendor_ramdisk_path = header_info.get('vendor_ramdisk_path')
                vendor_ramdisk_dir = header_info.get('vendor_ramdisk_dir')
                if vendor_ramdisk_path and vendor_ramdisk_dir and os.path.exists(vendor_ramdisk_dir):
                    vendor_compression = 'lz4' if vendor_ramdisk_path.endswith('.lz4') and lz4 else 'gzip'
                    repack_ramdisk(vendor_ramdisk_dir, vendor_ramdisk_path, vendor_compression)

        if args.operation in ["repack", "full"]:
            output_boot_img = os.path.join(output_dir, 'new-boot.img')
            repack_boot_image(header_info, output_dir, output_boot_img)
            print(f"New boot image created: {output_boot_img}")

    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
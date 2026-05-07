#!/usr/bin/env python3

import os
import sys
import platform
import subprocess
import hashlib
import json
import struct
from pathlib import Path
from datetime import datetime

class BinSearch:
    def __init__(self):
        self.os_type = self._detect_os()

    def _detect_os(self):
        system = platform.system().lower()
        if system == "linux":
            try:
                if "com.termux" in os.environ.get("PREFIX", ""):
                    return "termux"
            except:
                pass
            return "linux"
        elif system == "darwin":
            return "macos"
        elif system == "windows":
            return "windows"
        return "unknown"

    def _run_command(self, cmd):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout if result.returncode == 0 else None
        except:
            return None

    def analyze(self, binary_path):
        info = {
            'path': str(Path(binary_path).absolute()),
            'exists': Path(binary_path).exists(),
            'os': self.os_type,
            'timestamp': datetime.now().isoformat()
        }

        if not info['exists']:
            info['error'] = 'File not found'
            return info

        try:
            stat = Path(binary_path).stat()
            info['size_bytes'] = stat.st_size
            info['size_kb'] = round(stat.st_size / 1024, 2)
            info['size_mb'] = round(stat.st_size / 1024 / 1024, 2)

            with open(binary_path, 'rb') as f:
                header = f.read(16)

            if header[:4] == b'\x7fELF':
                info['binary_type'] = 'ELF'
                info['is_executable'] = True
            elif header[:2] == b'MZ':
                info['binary_type'] = 'PE'
                info['is_executable'] = True
            else:
                info['binary_type'] = 'Data file'
                info['is_executable'] = False

            sha256 = hashlib.sha256()
            with open(binary_path, 'rb') as f:
                sha256.update(f.read(1024 * 1024))
            info['fingerprint'] = sha256.hexdigest()[:16]

            strings = self._extract_strings(binary_path)
            info['strings_count'] = len(strings)
            info['sample_strings'] = strings[:20]

            functions = self._find_functions(binary_path)
            info['functions_count'] = len(functions)
            info['sample_functions'] = functions[:20]

            warnings = self._scan_suspicious(binary_path)
            info['warnings'] = warnings

            dependencies = self._get_dependencies(binary_path)
            info['dependencies'] = dependencies[:10]

        except Exception as e:
            info['error'] = str(e)

        return info

    def _extract_strings(self, binary_path, min_len=4):
        strings = []
        try:
            with open(binary_path, 'rb', errors='ignore') as f:
                data = f.read(1024 * 500)

            current = ''
            for byte in data:
                if 32 <= byte <= 126:
                    current += chr(byte)
                else:
                    if len(current) >= min_len:
                        strings.append(current)
                    current = ''
            if len(current) >= min_len:
                strings.append(current)
        except:
            pass

        unique = []
        for s in strings:
            if s not in unique and not s.isdigit():
                unique.append(s)
        return unique[:100]

    def _find_functions(self, binary_path):
        functions = []

        if self.os_type in ['linux', 'termux']:
            output = self._run_command(['nm', '-D', binary_path])
            if not output:
                output = self._run_command(['readelf', '-s', binary_path])

            if output:
                for line in output.split('\n'):
                    if 'FUNC' in line or 'T ' in line or 'D ' in line:
                        parts = line.split()
                        for part in parts:
                            if part and part[0].isalpha() and len(part) > 2:
                                if part not in functions and not part.startswith('_'):
                                    functions.append(part)
                                    break

        elif self.os_type == 'macos':
            output = self._run_command(['nm', '-gU', binary_path])
            if output:
                for line in output.split('\n'):
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] in ['T', 'D', 'S']:
                        func = parts[2]
                        if not func.startswith('_'):
                            functions.append(func)

        else:
            strings = self._extract_strings(binary_path, 3)
            for s in strings:
                if '(' in s or ')' in s or '::' in s:
                    functions.append(s[:50])

        return list(dict.fromkeys(functions))[:50]

    def _scan_suspicious(self, binary_path):
        warnings = []
        try:
            with open(binary_path, 'rb') as f:
                data = f.read(1024 * 100)

            patterns = [
                (b'http://', 'HTTP URL found'),
                (b'https://', 'HTTPS URL found'),
                (b'cmd.exe', 'Windows command'),
                (b'/bin/sh', 'Shell access'),
                (b'crypt', 'Cryptography'),
                (b'encrypt', 'Encryption'),
                (b'decrypt', 'Decryption'),
                (b'password', 'Password string'),
                (b'secret', 'Secret string'),
                (b'root', 'Root access'),
                (b'sudo', 'Sudo access'),
                (b'chmod', 'Permission change'),
                (b'chown', 'Owner change'),
                (b'mkfifo', 'FIFO creation'),
                (b'socket', 'Network socket'),
                (b'connect', 'Network connect'),
                (b'listen', 'Network listen'),
                (b'execve', 'Execute process'),
                (b'fork', 'Process fork'),
                (b'ptrace', 'Process tracing'),
            ]

            for pattern, desc in patterns:
                if pattern in data:
                    warnings.append(desc)
        except:
            pass

        return list(dict.fromkeys(warnings))

    def _get_dependencies(self, binary_path):
        deps = []

        if self.os_type in ['linux', 'termux']:
            output = self._run_command(['ldd', binary_path])
            if output:
                for line in output.split('\n'):
                    if '=>' in line:
                        parts = line.split('=>')
                        if len(parts) >= 2:
                            lib = parts[0].strip()
                            if lib not in deps:
                                deps.append(lib)

        elif self.os_type == 'macos':
            output = self._run_command(['otool', '-L', binary_path])
            if output:
                for line in output.split('\n')[1:]:
                    if line.strip():
                        lib = line.strip().split()[0]
                        if lib not in deps:
                            deps.append(lib)

        return deps

    def search_pattern(self, binary_path, pattern, pattern_type='hex'):
        results = []

        try:
            if pattern_type == 'hex':
                pattern_bytes = bytes.fromhex(pattern.replace(' ', ''))
            elif pattern_type == 'string':
                pattern_bytes = pattern.encode('utf-8')
            else:
                return [{'error': 'Invalid pattern type'}]

            with open(binary_path, 'rb') as f:
                data = f.read()

            pos = 0
            while True:
                pos = data.find(pattern_bytes, pos)
                if pos == -1:
                    break

                context_start = max(0, pos - 32)
                context_end = min(len(data), pos + len(pattern_bytes) + 32)

                results.append({
                    'offset_hex': hex(pos),
                    'offset_dec': pos,
                    'context_hex': data[context_start:context_end].hex(),
                    'context_ascii': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[context_start:context_end])
                })
                pos += 1
        except Exception as e:
            results.append({'error': str(e)})

        return results

    def compare(self, file1, file2):
        result = {
            'file1': file1,
            'file2': file2,
            'similarity': 0
        }

        try:
            with open(file1, 'rb') as f:
                data1 = f.read(1024 * 100)
            with open(file2, 'rb') as f:
                data2 = f.read(1024 * 100)

            min_len = min(len(data1), len(data2))
            if min_len > 0:
                matches = sum(1 for i in range(min_len) if data1[i] == data2[i])
                result['similarity'] = round((matches / min_len) * 100, 2)
                result['bytes_compared'] = min_len

            hash1 = hashlib.md5(data1[:1024]).hexdigest()
            hash2 = hashlib.md5(data2[:1024]).hexdigest()
            result['header_match'] = (hash1 == hash2)

        except Exception as e:
            result['error'] = str(e)

        return result

    def export_report(self, binary_path, output_file=None):
        analysis = self.analyze(binary_path)

        if output_file is None:
            output_file = f"report_{Path(binary_path).name}.json"

        with open(output_file, 'w') as f:
            json.dump(analysis, f, indent=2)

        return output_file

def main():
    if len(sys.argv) < 2:
        print("BinSearch - Binary Analysis Tool")
        print("")
        print("Usage:")
        print("  python binsearch_full.py <file> analyze")
        print("  python binsearch_full.py <file> search-hex <pattern>")
        print("  python binsearch_full.py <file> search-string <text>")
        print("  python binsearch_full.py <file1> compare <file2>")
        print("  python binsearch_full.py <file> export")
        print("")
        print("Examples:")
        print("  python binsearch_full.py /bin/ls analyze")
        print("  python binsearch_full.py /bin/ls search-hex 7F454C46")
        print("  python binsearch_full.py /bin/ls search-string libc")
        print("  python binsearch_full.py file1.so compare file2.so")
        sys.exit(1)

    file_path = sys.argv[1]
    bs = BinSearch()

    if not Path(file_path).exists() and sys.argv[2] not in ['compare']:
        print(f"Error: {file_path} not found")
        sys.exit(1)

    if len(sys.argv) == 2 or sys.argv[2] == 'analyze':
        result = bs.analyze(file_path)
        print(json.dumps(result, indent=2))

    elif sys.argv[2] == 'search-hex' and len(sys.argv) > 3:
        results = bs.search_pattern(file_path, sys.argv[3], 'hex')
        print(f"Found {len([r for r in results if 'error' not in r])} matches:")
        for r in results:
            if 'error' in r:
                print(f"Error: {r['error']}")
            else:
                print(f"  Offset: {r['offset_hex']}")

    elif sys.argv[2] == 'search-string' and len(sys.argv) > 3:
        results = bs.search_pattern(file_path, sys.argv[3], 'string')
        print(f"Found {len([r for r in results if 'error' not in r])} matches:")
        for r in results:
            if 'error' not in r:
                print(f"  Offset: {r['offset_hex']}")

    elif sys.argv[2] == 'compare' and len(sys.argv) > 3:
        result = bs.compare(file_path, sys.argv[3])
        print(json.dumps(result, indent=2))

    elif sys.argv[2] == 'export':
        output = bs.export_report(file_path)
        print(f"Report exported to: {output}")

    else:
        print("Unknown command. Use: analyze, search-hex, search-string, compare, export")

if __name__ == '__main__':
    main()

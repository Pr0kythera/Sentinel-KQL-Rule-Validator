#!/usr/bin/env python3
"""
PE Malware Detection Script - Corrected Version
Extracts all 74 features required by the trained model

Feature Categories:
1. DOS_HEADER (17 features) - Legacy DOS compatibility header
2. FILE_HEADER (6 features) - COFF file header
3. OPTIONAL_HEADER (24 features) - PE-specific header
4. Section Statistics (15 features) - Calculated from section table
5. Behavioral Analysis (2 features) - Suspicious patterns
6. Directory Entries (8 features) - Data directory presence/size
7. Missing OPTIONAL_HEADER (2 features) - Magic number
"""

import sys
import os
import pickle
import pefile
import pandas as pd
import numpy as np
import warnings
from typing import Dict, Tuple, Optional, List

# Suppress warnings
warnings.filterwarnings("ignore")

# ============================================================================
# SUSPICIOUS INDICATORS
# ============================================================================

SUSPICIOUS_IMPORTS = {
    # Process manipulation
    'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
    'WriteProcessMemory', 'ReadProcessMemory', 'CreateRemoteThread',
    'OpenProcess', 'TerminateProcess', 'GetProcAddress', 'LoadLibraryA',
    'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW',
    
    # Code injection
    'NtQueueApcThread', 'QueueUserAPC', 'SetWindowsHookEx', 'RtlCreateUserThread',
    'NtCreateThreadEx', 'CreateThread', 'ResumeThread', 'SuspendThread',
    
    # Memory manipulation
    'RtlMoveMemory', 'memcpy', 'NtWriteVirtualMemory', 'NtReadVirtualMemory',
    'NtAllocateVirtualMemory', 'NtProtectVirtualMemory',
    
    # Debugging/Anti-analysis
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
    'OutputDebugStringA', 'OutputDebugStringW', 'DebugActiveProcess',
    
    # Registry manipulation
    'RegOpenKeyExA', 'RegOpenKeyExW', 'RegSetValueExA', 'RegSetValueExW',
    'RegCreateKeyExA', 'RegCreateKeyExW', 'RegDeleteKeyA', 'RegDeleteKeyW',
    
    # File operations
    'CreateFileA', 'CreateFileW', 'WriteFile', 'ReadFile', 'DeleteFileA',
    'DeleteFileW', 'MoveFileA', 'MoveFileW', 'CopyFileA', 'CopyFileW',
    
    # Network operations
    'WSAStartup', 'socket', 'connect', 'send', 'recv', 'InternetOpenA',
    'InternetOpenW', 'InternetOpenUrlA', 'InternetOpenUrlW', 'HttpSendRequestA',
    'HttpSendRequestW', 'URLDownloadToFileA', 'URLDownloadToFileW',
    
    # Cryptography
    'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContextA', 'CryptAcquireContextW',
    'CryptCreateHash', 'CryptHashData', 'CryptDeriveKey',
    
    # Privilege escalation
    'AdjustTokenPrivileges', 'OpenProcessToken', 'LookupPrivilegeValueA',
    'LookupPrivilegeValueW', 'ImpersonateLoggedOnUser',
    
    # Service manipulation
    'CreateServiceA', 'CreateServiceW', 'OpenServiceA', 'OpenServiceW',
    'StartServiceA', 'StartServiceW', 'ControlService', 'DeleteService',
    
    # Keylogging
    'GetAsyncKeyState', 'GetKeyState', 'GetForegroundWindow', 'SetWindowsHookExA',
    'SetWindowsHookExW', 'CallNextHookEx',
    
    # Evasion
    'Sleep', 'GetTickCount', 'GetSystemTime', 'GetLocalTime',
}

SUSPICIOUS_SECTION_NAMES = {
    '.upx', 'upx0', 'upx1', 'upx2',  # UPX packer
    '.aspack', '.adata', '.asdata',  # ASPack packer
    '.petite', '.pec1', '.pec2',     # PEtite packer
    '.neolite',                       # Neolite packer
    '.themida', '.winlicense',        # Themida/Winlicense
    '.vmprotect',                     # VMProtect
    '.mpress',                        # MPRESS
    '.packed', '.pdata',              # Generic packed indicators
    'text', 'CODE', 'DATA',           # Non-standard naming (missing dot)
}


# ============================================================================
# RESOURCE LOADING
# ============================================================================

def load_resources() -> Tuple[object, List[str]]:
    """
    Load the trained model and the column list.
    
    Returns:
        Tuple of (model, columns list)
    
    Raises:
        FileNotFoundError: If model files are missing
        Exception: If model files are corrupted
    """
    try:
        base_path = os.path.dirname(os.path.abspath(__file__))
        
        model_path = os.path.join(base_path, 'malware_detector.pkl')
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")
            
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
            
        columns_path = os.path.join(base_path, 'model_columns.pkl')
        if not os.path.exists(columns_path):
            raise FileNotFoundError(f"Columns file not found: {columns_path}")
            
        with open(columns_path, 'rb') as f:
            columns = pickle.load(f)
        
        # Validate model has required methods
        if not hasattr(model, 'predict') or not hasattr(model, 'predict_proba'):
            raise ValueError("Loaded object is not a valid classifier model")
            
        if not hasattr(model, 'feature_importances_'):
            print("Warning: Model does not have feature_importances_ attribute")
            
        print(f"[+] Loaded model expecting {len(columns)} features")
        return model, columns
        
    except FileNotFoundError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error loading model files: {e}")
        sys.exit(1)


# ============================================================================
# CATEGORY 1: DOS_HEADER EXTRACTION (17 features)
# ============================================================================

def extract_dos_header(pe: pefile.PE) -> Dict[str, int]:
    """
    Extract DOS header features (e_* fields).
    
    The DOS header is a legacy structure from MS-DOS compatibility.
    Malware often manipulates these fields for evasion.
    
    Args:
        pe: pefile.PE object
        
    Returns:
        Dictionary with 17 DOS header features
    """
    dos = {}
    
    if hasattr(pe, 'DOS_HEADER'):
        dh = pe.DOS_HEADER
        
        dos['e_magic'] = dh.e_magic          # Magic number (should be 0x5A4D = "MZ")
        dos['e_cblp'] = dh.e_cblp            # Bytes on last page of file
        dos['e_cp'] = dh.e_cp                # Pages in file
        dos['e_crlc'] = dh.e_crlc            # Relocations
        dos['e_cparhdr'] = dh.e_cparhdr      # Size of header in paragraphs
        dos['e_minalloc'] = dh.e_minalloc    # Minimum extra paragraphs needed
        dos['e_maxalloc'] = dh.e_maxalloc    # Maximum extra paragraphs needed
        dos['e_ss'] = dh.e_ss                # Initial (relative) SS value
        dos['e_sp'] = dh.e_sp                # Initial SP value
        dos['e_csum'] = dh.e_csum            # Checksum
        dos['e_ip'] = dh.e_ip                # Initial IP value
        dos['e_cs'] = dh.e_cs                # Initial (relative) CS value
        dos['e_lfarlc'] = dh.e_lfarlc        # File address of relocation table
        dos['e_ovno'] = dh.e_ovno            # Overlay number
        dos['e_oemid'] = dh.e_oemid          # OEM identifier
        dos['e_oeminfo'] = dh.e_oeminfo      # OEM information
        dos['e_lfanew'] = dh.e_lfanew        # File address of new exe header (PE header offset)
    
    return dos


# ============================================================================
# CATEGORY 2: FILE_HEADER EXTRACTION (6 features)
# ============================================================================

def extract_file_header(pe: pefile.PE) -> Dict[str, int]:
    """
    Extract COFF file header features.
    
    The FILE_HEADER contains critical metadata about the PE file structure.
    
    Args:
        pe: pefile.PE object
        
    Returns:
        Dictionary with 6 FILE_HEADER features
    """
    fh = {}
    
    if hasattr(pe, 'FILE_HEADER'):
        file_hdr = pe.FILE_HEADER
        
        # Machine type (e.g., 0x14c = x86, 0x8664 = x64)
        fh['Machine'] = file_hdr.Machine
        
        # Number of sections in the file
        fh['NumberOfSections'] = file_hdr.NumberOfSections
        
        # Pointer to COFF symbol table (usually 0 for executables)
        fh['PointerToSymbolTable'] = file_hdr.PointerToSymbolTable
        
        # Number of entries in symbol table
        fh['NumberOfSymbols'] = file_hdr.NumberOfSymbols
        
        # Size of optional header
        fh['SizeOfOptionalHeader'] = file_hdr.SizeOfOptionalHeader
        
        # File characteristics (flags like executable, DLL, etc.)
        # Common flags: 0x0002 = EXECUTABLE_IMAGE, 0x2000 = DLL
        fh['Characteristics'] = file_hdr.Characteristics
    
    return fh


# ============================================================================
# CATEGORY 3: OPTIONAL_HEADER EXTRACTION (24 features)
# ============================================================================

def extract_optional_header(pe: pefile.PE) -> Dict[str, int]:
    """
    Extract OPTIONAL_HEADER features.
    
    Despite the name, this header is mandatory for executables.
    Contains crucial information about how to load and execute the PE.
    
    Args:
        pe: pefile.PE object
        
    Returns:
        Dictionary with 26 OPTIONAL_HEADER features (including Magic)
    """
    opt = {}
    
    if hasattr(pe, 'OPTIONAL_HEADER'):
        oh = pe.OPTIONAL_HEADER
        
        # Magic number (0x10b = PE32, 0x20b = PE32+/64-bit)
        opt['Magic'] = oh.Magic
        
        # Linker version
        opt['MajorLinkerVersion'] = oh.MajorLinkerVersion
        opt['MinorLinkerVersion'] = oh.MinorLinkerVersion
        
        # Code and data sizes
        opt['SizeOfCode'] = oh.SizeOfCode
        opt['SizeOfInitializedData'] = oh.SizeOfInitializedData
        opt['SizeOfUninitializedData'] = oh.SizeOfUninitializedData
        
        # Entry point RVA (Relative Virtual Address)
        opt['AddressOfEntryPoint'] = oh.AddressOfEntryPoint
        
        # Base addresses
        opt['BaseOfCode'] = oh.BaseOfCode
        opt['ImageBase'] = oh.ImageBase
        
        # Alignment values
        opt['SectionAlignment'] = oh.SectionAlignment  # In memory
        opt['FileAlignment'] = oh.FileAlignment        # On disk
        
        # Version information
        opt['MajorImageVersion'] = oh.MajorImageVersion
        opt['MinorImageVersion'] = oh.MinorImageVersion
        opt['MajorSubsystemVersion'] = oh.MajorSubsystemVersion
        opt['MinorSubsystemVersion'] = oh.MinorSubsystemVersion
        
        # Image sizes
        opt['SizeOfHeaders'] = oh.SizeOfHeaders
        opt['CheckSum'] = oh.CheckSum
        opt['SizeOfImage'] = oh.SizeOfImage
        
        # Subsystem (3 = Console, 2 = GUI, etc.)
        opt['Subsystem'] = oh.Subsystem
        
        # DLL characteristics (ASLR, DEP, etc.)
        opt['DllCharacteristics'] = oh.DllCharacteristics
        
        # Stack and heap sizes
        opt['SizeOfStackReserve'] = oh.SizeOfStackReserve
        opt['SizeOfStackCommit'] = oh.SizeOfStackCommit
        opt['SizeOfHeapReserve'] = oh.SizeOfHeapReserve
        opt['SizeOfHeapCommit'] = oh.SizeOfHeapCommit
        
        # Loader flags (obsolete but may be set)
        opt['LoaderFlags'] = oh.LoaderFlags
        
        # Number of data directories
        opt['NumberOfRvaAndSizes'] = oh.NumberOfRvaAndSizes
    
    return opt


# ============================================================================
# CATEGORY 4: SECTION STATISTICS (15 features)
# ============================================================================

def extract_section_statistics(pe: pefile.PE) -> Dict[str, float]:
    """
    Calculate statistical features from PE sections.
    
    Sections contain code, data, resources, etc. Unusual section
    characteristics often indicate packing or malicious modifications.
    
    Args:
        pe: pefile.PE object
        
    Returns:
        Dictionary with 15 section-related features
    """
    sections = {}
    
    if not hasattr(pe, 'sections') or len(pe.sections) == 0:
        # No sections - highly unusual, fill with zeros
        sections['SectionsLength'] = 0
        sections['SectionMinEntropy'] = 0
        sections['SectionMaxEntropy'] = 0
        sections['SectionMinRawsize'] = 0
        sections['SectionMaxRawsize'] = 0
        sections['SectionMinVirtualsize'] = 0
        sections['SectionMaxVirtualsize'] = 0
        sections['SectionMaxPhysical'] = 0
        sections['SectionMinPhysical'] = 0
        sections['SectionMaxVirtual'] = 0
        sections['SectionMinVirtual'] = 0
        sections['SectionMaxPointerData'] = 0
        sections['SectionMinPointerData'] = 0
        sections['SectionMaxChar'] = 0
        sections['SectionMainChar'] = 0
        return sections
    
    # Collect section metrics
    entropies = []
    raw_sizes = []
    virtual_sizes = []
    physical_addresses = []
    virtual_addresses = []
    pointer_to_raw_data = []
    characteristics = []
    
    for section in pe.sections:
        # Entropy (high entropy = encrypted/packed)
        entropies.append(section.get_entropy())
        
        # Raw size (on disk)
        raw_sizes.append(section.SizeOfRawData)
        
        # Virtual size (in memory)
        virtual_sizes.append(section.Misc_VirtualSize)
        
        # Physical address (deprecated but sometimes set)
        if hasattr(section, 'Misc_PhysicalAddress'):
            physical_addresses.append(section.Misc_PhysicalAddress)
        else:
            physical_addresses.append(0)
        
        # Virtual address (RVA where section is loaded)
        virtual_addresses.append(section.VirtualAddress)
        
        # Pointer to raw data (file offset)
        pointer_to_raw_data.append(section.PointerToRawData)
        
        # Characteristics (flags: readable, writable, executable, etc.)
        characteristics.append(section.Characteristics)
    
    # Calculate statistics
    sections['SectionsLength'] = len(pe.sections)
    
    # Entropy statistics
    sections['SectionMinEntropy'] = min(entropies) if entropies else 0
    sections['SectionMaxEntropy'] = max(entropies) if entropies else 0
    
    # Size statistics
    sections['SectionMinRawsize'] = min(raw_sizes) if raw_sizes else 0
    sections['SectionMaxRawsize'] = max(raw_sizes) if raw_sizes else 0
    sections['SectionMinVirtualsize'] = min(virtual_sizes) if virtual_sizes else 0
    sections['SectionMaxVirtualsize'] = max(virtual_sizes) if virtual_sizes else 0
    
    # Physical address statistics
    sections['SectionMaxPhysical'] = max(physical_addresses) if physical_addresses else 0
    sections['SectionMinPhysical'] = min(physical_addresses) if physical_addresses else 0
    
    # Virtual address statistics
    sections['SectionMaxVirtual'] = max(virtual_addresses) if virtual_addresses else 0
    sections['SectionMinVirtual'] = min(virtual_addresses) if virtual_addresses else 0
    
    # Pointer to raw data statistics
    sections['SectionMaxPointerData'] = max(pointer_to_raw_data) if pointer_to_raw_data else 0
    sections['SectionMinPointerData'] = min(pointer_to_raw_data) if pointer_to_raw_data else 0
    
    # Characteristics statistics
    sections['SectionMaxChar'] = max(characteristics) if characteristics else 0
    # Note: SectionMainChar likely means "most common characteristics"
    # Using the first section's characteristics as heuristic
    sections['SectionMainChar'] = characteristics[0] if characteristics else 0
    
    return sections


# ============================================================================
# CATEGORY 5: BEHAVIORAL ANALYSIS (2 features)
# ============================================================================

def extract_behavioral_features(pe: pefile.PE) -> Dict[str, int]:
    """
    Analyze behavioral indicators of maliciousness.
    
    These features look for suspicious patterns in imports and section names
    that are common in malware.
    
    Args:
        pe: pefile.PE object
        
    Returns:
        Dictionary with 2 behavioral features
    """
    behavioral = {}
    
    # Feature 1: Count suspicious import functions
    suspicious_import_count = 0
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    # Decode bytes to string if necessary
                    import_name = imp.name.decode('utf-8') if isinstance(imp.name, bytes) else imp.name
                    if import_name in SUSPICIOUS_IMPORTS:
                        suspicious_import_count += 1
    
    behavioral['SuspiciousImportFunctions'] = suspicious_import_count
    
    # Feature 2: Check for suspicious section names
    suspicious_section_count = 0
    
    if hasattr(pe, 'sections'):
        for section in pe.sections:
            # Get section name and clean it
            section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00').lower()
            
            # Check against known packer/suspicious names
            if section_name in SUSPICIOUS_SECTION_NAMES:
                suspicious_section_count += 1
            
            # Also check for sections without leading dot (non-standard)
            if section_name and not section_name.startswith('.'):
                suspicious_section_count += 1
    
    behavioral['SuspiciousNameSection'] = suspicious_section_count
    
    return behavioral


# ============================================================================
# CATEGORY 6: DIRECTORY ENTRIES (8 features)
# ============================================================================

def extract_directory_entries(pe: pefile.PE) -> Dict[str, int]:
    """
    Extract data directory presence and size information.
    
    Data directories point to important structures like imports, exports,
    resources, etc. Their presence and size can indicate malicious behavior.
    
    Args:
        pe: pefile.PE object
        
    Returns:
        Dictionary with 8 directory entry features
    """
    directories = {}
    
    # Initialize all to 0
    directories['DirectoryEntryImport'] = 0
    directories['DirectoryEntryImportSize'] = 0
    directories['DirectoryEntryExport'] = 0
    directories['ImageDirectoryEntryExport'] = 0
    directories['ImageDirectoryEntryImport'] = 0
    directories['ImageDirectoryEntryResource'] = 0
    directories['ImageDirectoryEntryException'] = 0
    directories['ImageDirectoryEntrySecurity'] = 0
    
    if not hasattr(pe, 'OPTIONAL_HEADER'):
        return directories
    
    # Check if DATA_DIRECTORY exists
    if not hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
        return directories
    
    # Data directory indices (from PE specification)
    # 0 = Export, 1 = Import, 2 = Resource, 3 = Exception, 4 = Security, etc.
    data_dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    
    # DirectoryEntryExport (index 0)
    if len(data_dirs) > 0:
        directories['DirectoryEntryExport'] = 1 if data_dirs[0].VirtualAddress != 0 else 0
        directories['ImageDirectoryEntryExport'] = data_dirs[0].Size
    
    # DirectoryEntryImport (index 1)
    if len(data_dirs) > 1:
        directories['DirectoryEntryImport'] = 1 if data_dirs[1].VirtualAddress != 0 else 0
        directories['DirectoryEntryImportSize'] = data_dirs[1].Size
        directories['ImageDirectoryEntryImport'] = data_dirs[1].Size
    
    # DirectoryEntryResource (index 2)
    if len(data_dirs) > 2:
        directories['ImageDirectoryEntryResource'] = data_dirs[2].Size
    
    # DirectoryEntryException (index 3)
    if len(data_dirs) > 3:
        directories['ImageDirectoryEntryException'] = data_dirs[3].Size
    
    # DirectoryEntrySecurity (index 4)
    if len(data_dirs) > 4:
        directories['ImageDirectoryEntrySecurity'] = data_dirs[4].Size
    
    return directories


# ============================================================================
# MAIN FEATURE EXTRACTION
# ============================================================================

def extract_features(file_path: str, model_columns: List[str]) -> Optional[pd.DataFrame]:
    """
    Extract all 74 features from a PE file to match the model's schema.
    
    Args:
        file_path: Path to the PE file to analyze
        model_columns: List of column names expected by the model
        
    Returns:
        DataFrame with extracted features, or None on error
    """
    try:
        # Parse PE file
        pe = pefile.PE(file_path, fast_load=False)
        
        # Initialize feature dictionary
        data = {}
        
        # Extract all feature categories
        print("[*] Extracting DOS_HEADER features...")
        data.update(extract_dos_header(pe))
        
        print("[*] Extracting FILE_HEADER features...")
        data.update(extract_file_header(pe))
        
        print("[*] Extracting OPTIONAL_HEADER features...")
        data.update(extract_optional_header(pe))
        
        print("[*] Extracting section statistics...")
        data.update(extract_section_statistics(pe))
        
        print("[*] Extracting behavioral features...")
        data.update(extract_behavioral_features(pe))
        
        print("[*] Extracting directory entries...")
        data.update(extract_directory_entries(pe))
        
        # Close PE file
        pe.close()
        
        # Create DataFrame with exact column order from model
        features_df = pd.DataFrame([data], columns=model_columns)
        
        # Fill any missing values with 0
        features_df = features_df.fillna(0)
        
        # Verify feature count
        extracted_count = len([k for k in data.keys() if k in model_columns])
        print(f"[+] Extracted {extracted_count}/{len(model_columns)} features")
        
        if extracted_count < len(model_columns):
            missing = set(model_columns) - set(data.keys())
            print(f"[!] Warning: {len(missing)} features missing: {missing}")
        
        return features_df
        
    except pefile.PEFormatError as e:
        print(f"[!] Error: Not a valid PE file - {e}")
        return None
    except Exception as e:
        print(f"[!] Error parsing file: {e}")
        import traceback
        traceback.print_exc()
        return None


# ============================================================================
# PREDICTION EXPLANATION
# ============================================================================

def explain_prediction(model: object, columns: List[str], input_data: pd.DataFrame, top_n: int = 10) -> None:
    """
    Display the top N features that influenced the model's decision.
    
    Args:
        model: Trained model with feature_importances_ attribute
        columns: List of feature names
        input_data: DataFrame with extracted features
        top_n: Number of top features to display
    """
    # Check if model has feature importances
    if not hasattr(model, 'feature_importances_'):
        print("\n[!] Model does not support feature importance analysis")
        return
    
    # Get importance scores
    importances = model.feature_importances_
    
    # Sort by importance (descending)
    indices = np.argsort(importances)[::-1]
    
    print(f"\n" + "=" * 80)
    print(f"FEATURE IMPORTANCE ANALYSIS: Top {top_n} Features Driving Decision")
    print("=" * 80)
    print(f"{'Rank':<6} {'Feature Name':<35} {'File Value':<15} {'Importance':<12}")
    print("-" * 80)
    
    for rank, idx in enumerate(indices[:top_n], 1):
        feature_name = columns[idx]
        importance_score = importances[idx]
        file_value = input_data[feature_name].values[0]
        
        print(f"{rank:<6} {feature_name:<35} {file_value:<15.2f} {importance_score:<12.6f}")
    
    print("=" * 80)


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main execution function."""
    
    # Check command line arguments
    if len(sys.argv) != 2:
        print("Usage: python pe-extractor-corrected.py <path_to_file>")
        print("\nExample:")
        print("  python pe-extractor-corrected.py suspicious.exe")
        sys.exit(1)
    
    target_file = sys.argv[1]
    
    # Validate file exists
    if not os.path.exists(target_file):
        print(f"[!] Error: File '{target_file}' not found.")
        sys.exit(1)
    
    # Load model and columns
    print("[*] Loading model resources...")
    model, columns = load_resources()
    
    # Extract features
    print(f"\n[*] Analyzing: {target_file}")
    print("=" * 80)
    input_data = extract_features(target_file, columns)
    
    if input_data is None:
        print("[!] Feature extraction failed. Cannot proceed with prediction.")
        sys.exit(1)
    
    # Make prediction
    print("\n[*] Running classification...")
    prediction = model.predict(input_data)[0]
    probabilities = model.predict_proba(input_data)[0]
    
    # Display results
    print("\n" + "=" * 80)
    print("CLASSIFICATION RESULT")
    print("=" * 80)
    
    if prediction == 1:
        print("[!] VERDICT: MALWARE DETECTED")
        print(f"    Malware Confidence: {probabilities[1]:.2%}")
        print(f"    Benign Confidence:  {probabilities[0]:.2%}")
    else:
        print("[+] VERDICT: CLEAN FILE")
        print(f"    Benign Confidence:  {probabilities[0]:.2%}")
        print(f"    Malware Confidence: {probabilities[1]:.2%}")
    
    print("=" * 80)
    
    # Explain prediction
    explain_prediction(model, columns, input_data, top_n=15)
    
    print("\n[*] Analysis complete.")


if __name__ == "__main__":
    main()

"""QuickBooks content scanner for ransomware incident response.

Searches plaintext regions of encrypted evidence files for QuickBooks
indicator strings (Intuit, QuickBooks, QBFS, etc.) to locate company
files that lack clean magic-byte signatures.
"""

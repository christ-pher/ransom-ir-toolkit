"""Post-carve QuickBooks file validator.

Validates carved files from carve-vmdk output, classifying real
QuickBooks files (QBB, IIF, OFX) and filtering false positives
(Office documents, Java archives, corrupt ZIPs).
"""

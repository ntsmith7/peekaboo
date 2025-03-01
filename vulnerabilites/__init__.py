# Import and re-export the XSSScanner class directly from the xss.py file
from vulnerabilites.xss.xss import XSSScanner, XSSFinding, XSSContext

# Make these classes available when importing from vulnerabilites
__all__ = ['XSSScanner', 'XSSFinding', 'XSSContext']

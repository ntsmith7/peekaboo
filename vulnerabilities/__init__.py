# Import and expose classes from xss module
from vulnerabilities.xss.xss import XSSScanner, XSSFinding, XSSContext

# Make these classes available when importing from vulnerabilities
__all__ = ['XSSScanner', 'XSSFinding', 'XSSContext']

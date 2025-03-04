# Import and expose classes from xss.py using absolute import
from vulnerabilities.xss.xss import XSSScanner, XSSFinding, XSSContext

# Make these classes available when importing from vulnerabilities.xss
__all__ = ['XSSScanner', 'XSSFinding', 'XSSContext']

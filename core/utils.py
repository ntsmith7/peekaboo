def clean_target_url(target: str) -> str:
    """
    Standardize target URL format by removing common prefixes and trailing slashes.
    
    Args:
        target: The target URL or domain to clean
        
    Returns:
        Cleaned target string
    """
    target = target.lower()
    for prefix in ['https://', 'http://', 'www.']:
        if target.startswith(prefix):
            target = target[len(prefix):]
    return target.strip('/')

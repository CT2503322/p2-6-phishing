def is_dangerous(att):
    """Dangerous attachment extensions.
    """
    dangerous = ['.exe', '.scr', '.pif']
    return any(att.lower().endswith(ext) for ext in dangerous) if att else False

def archive_name_suspicious(att):
    """Suspicious archive names.
    """
    susp = ['.zip', '.rar', '.7z']
    if att and any(att.lower().endswith(ext) for ext in susp):
        # Check file size or something, but here just length
        return len(att) > 100
    return False
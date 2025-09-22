from bs4 import BeautifulSoup

def clean_html(html_content):
    """
    Clean HTML content using BeautifulSoup to extract readable text
    while removing CSS, scripts, and other artifacts.
    
    Args:
        html_content (str): Raw HTML content from email
    
    Returns:
        str: Clean, readable text
    """
    if not html_content:
        return ""
    
    try:
        # Parse HTML with BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.extract()
        
        # Remove hidden elements (normally not visible)
        for hidden in soup.find_all(style=lambda x: x and 'display:none' in x):
            hidden.extract()
        
        # Extract text while trying to preserve some structure
        clean_text = soup.get_text(separator='\n', strip=True)
        
        # Clean up excessive whitespace and newlines
        lines = [line.strip() for line in clean_text.split('\n') if line.strip()]
        
        return '\n'.join(lines)
    
    except Exception as e:
        print(f"Error parsing HTML content: {e}")
        # Fallback: return original content if parsing fails
        return html_content.strip()

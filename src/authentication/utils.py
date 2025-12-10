"""
Utility functions for authentication
"""


def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_user_agent(request):
    """Get user agent from request"""
    return request.META.get('HTTP_USER_AGENT', '')[:512]


def create_fingerprint(request):
    """
    Create a client fingerprint for additional security
    Combines IP and User-Agent
    """
    import hashlib
    
    ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    
    fingerprint_string = f"{ip}:{user_agent}"
    return hashlib.sha256(fingerprint_string.encode()).hexdigest()

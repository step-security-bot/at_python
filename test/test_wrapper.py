import os, unittest

def skip_if_dependabot_pr(func):
    """Decorator for skipping a test method if it's a Dependabot PR."""
    if int(os.getenv('DEPENDABOT_PR')):
        return unittest.skip("Dependabot PR")(func)
    else:
        return func
    
if __name__ == '__main__':
    pass
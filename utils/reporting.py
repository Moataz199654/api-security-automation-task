import os
from datetime import datetime
from pathlib import Path

def create_report_directory():
    """
    Create the reports directory if it doesn't exist
    """
    reports_dir = Path(__file__).parent.parent / 'reports'
    reports_dir.mkdir(exist_ok=True)
    return reports_dir

def generate_report_name():
    """
    Generate a unique report filename based on timestamp
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f'security_report_{timestamp}.html'

def save_test_artifacts(test_name, artifacts):
    """
    Save test artifacts (screenshots, logs, etc.) to the reports directory
    """
    reports_dir = create_report_directory()
    artifact_dir = reports_dir / test_name
    artifact_dir.mkdir(exist_ok=True)
    
    for name, content in artifacts.items():
        artifact_path = artifact_dir / name
        with open(artifact_path, 'w') as f:
            f.write(content)

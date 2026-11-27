"""
MedVault Application Runner
"""
import os
from app import create_app
from config import Config, DevelopmentConfig

env = os.environ.get('FLASK_ENV', 'development')
config_class = DevelopmentConfig if env == 'development' else Config

app = create_app(config_class)

if __name__ == '__main__':
    # Binds to 127.0.0.1; debug=False to avoid arbitrary code execution vulnerabilities
    app.run(host='127.0.0.1', port=5000, debug=False)

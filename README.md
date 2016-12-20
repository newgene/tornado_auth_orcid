# tornado_auth_orcid
ORCID authentication backend for tornado

# Install requirements
```
pip install -r requirements.txt
```

# Config
Put into `config.py` following values
```
ORCID_CLIENT_ID = "<CLIENT-ID>"
ORCID_CLIENT_SECRET = "<CLIENT-SECRET>"
GOOGLE_KEY = ""
GOOGLE_SECRET = ""

SMTP_SERVER = "localhost"
SMTP_PORT = 1025
SMTP_USERNAME = ""
SMTP_PASSWORD = ""
FROM_EMAIL = "<FROM-EMAIL>"

ELASTICSEARCH_HOST = "localhost"
ELASTICSEARCH_PORT = 9200
```
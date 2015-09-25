import sys

# Python 2.7.9 and later supports SSL certificate verification
# Previous versions require a custom HTTPS handler.
if sys.version_info[1] == 7 and sys.version_info[2] >= 9:
    USE_CUSTOM_HTTPS_HANDLER = False
else:
    USE_CUSTOM_HTTPS_HANDLER = True

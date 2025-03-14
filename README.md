# MITM_CONTENT_FILTER
A powerful MITM (Man-in-the-Middle) and Flask-based tool for monitoring and filtering HTTP/HTTPS traffic. It enhances user privacy by logging, inspecting, and blocking malicious or unwanted requests using custom filters and external threat intelligence (AbuseIPDB).

# FEATURES:
Real-Time Traffic Inspection: Capture and analyze packets via scapy and mitmproxy.

Threat Detection: Check IP addresses against AbuseIPDB and block high-risk sources.
Custom Filtering: Block based on URLs, keywords, file types, and IP addresses.

Logging System: Store and retrieve traffic logs with SQLite for easy analysis.

Flask API: Manage filters and view logs via a RESTful API.

Cross-Platform: Works on Linux and Windows with automatic firewall rules.

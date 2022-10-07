FROM mauricelambert/webscripts

RUN rm -f /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/config/server.json
COPY server.json /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/config/

RUN rm -f /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/config/scripts/default_*.json
COPY vulns.json /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/config/scripts/

COPY check_up.py /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/scripts/vulnerabilities/
COPY fileshare.py /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/scripts/vulnerabilities/
COPY num_usages.py /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/scripts/vulnerabilities/
COPY password_manager.py /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/scripts/vulnerabilities/
COPY xml_counter.py /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/scripts/vulnerabilities/
COPY xml_to_html.py /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/scripts/vulnerabilities/
COPY .credentials /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/scripts/vulnerabilities/

RUN python3 /usr/src/WebScripts/lib/python3.9/site-packages/WebScripts/scripts/account/change_user_password.py 2 Adm1n

# shodan-vuln-parser
A quick Python3 script to parse .json.gz Shodan download files and output a CSV with vulnerability information.

## Notice:
This is a very hastily written/quick win script. If anyone else happens to have utility for this outside of me, then let me know and I can spend some time cleaning it up.

## To Run:

python3 getthemCVEs.py <directory containing .json.gz files>

### Credit: Majority of script taken from a gist - thesubtlety/parse-shodan-vuln-data.py. Updated the script to include SSL cert information to help identify individual IPs at a glance. 

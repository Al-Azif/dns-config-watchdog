# DNS Config Watchdog

## Summary
Compiles the required files to update a BIND DNS server from a JSON file.

This method was chosen so we can use regex to make the zone files vs trying to make all the different options and manage it. The server can be easily updated from Github on a schedule by setting up a cron job to up run a git pull on this repo using a watchdog or via remote file fetching.

## CLI Args
- `--cwd`: Output the files into the current working directory. Do this __before__ submitting a pull request, it's easy to mess up the regex. Having a single unescaped `.` adds a lot of broken records.
- `--remote https://example.com/zones.json`: pulls the `zones.json` file from the specified HTTP(S) source.
- `--watchdog`: Runs the process as a watchdog to watch `zone.json` for modification. Cannot run with the `--remote` arg.

## Notes
- Paths/Filenames are all hardcoded
- Use {{SELF}} if you'd like the IP to be the IP of the server it runs on
- Use {{BLOCKED}} if you'd like to block that domain vs making an individual zone file for that domain
- Careful with the regex
- Built for Python 3.6+ on Ubuntu 18.04. You may need to tweak it to work on other systems.
- You'll notice thinks like akamai, edgekey, llnwd, ribob01, etc aren't blocked.... THIS IS ON PURPOSE. They are CDNs that don't have anything to do with actually OS functionality, but will break some media apps for no reason. In fact most of them are not even accessed if the playstation root domains are blocked.

## Example
- For the DNS server I host I used to use a cron job to run `python3 /opt/dns-config-watchdog/main.py --remote https://raw.githubusercontent.com/Al-Azif/dns-config-watchdog/master/zones.json` every day at 00:00 server time.

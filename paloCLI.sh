set cli scripting-mode on
configure

# --- Optional cleanup (makes the script idempotent) ---
delete vsys vsys1 rulebase security rules "Ubuntu Ecom IN"
delete vsys vsys1 rulebase security rules "Webmail Fedora - smtp and pop3"
delete vsys vsys1 rulebase security rules "Splunk - IN"
delete vsys vsys1 rulebase security rules "internal - out"
delete vsys vsys1 rulebase security rules "any to any"
delete vsys vsys1 rulebase security rules "drop external - in"

# --- Rule 1: Ubuntu Ecom IN ---
set vsys vsys1 rulebase security rules "Ubuntu Ecom IN" from any
set vsys vsys1 rulebase security rules "Ubuntu Ecom IN" to internal
set vsys vsys1 rulebase security rules "Ubuntu Ecom IN" source any
set vsys vsys1 rulebase security rules "Ubuntu Ecom IN" destination 172.25.25.11
set vsys vsys1 rulebase security rules "Ubuntu Ecom IN" application web-browsing
set vsys vsys1 rulebase security rules "Ubuntu Ecom IN" application http-tunnel
set vsys vsys1 rulebase security rules "Ubuntu Ecom IN" service service-http
set vsys vsys1 rulebase security rules "Ubuntu Ecom IN" action allow
set vsys vsys1 rulebase security rules "Ubuntu Ecom IN" log-start yes

# --- Rule 2: Webmail Fedora - smtp and pop3 ---
set vsys vsys1 rulebase security rules "Webmail Fedora - smtp and pop3" from any
set vsys vsys1 rulebase security rules "Webmail Fedora - smtp and pop3" to internal
set vsys vsys1 rulebase security rules "Webmail Fedora - smtp and pop3" source any
set vsys vsys1 rulebase security rules "Webmail Fedora - smtp and pop3" destination 172.25.25.39
set vsys vsys1 rulebase security rules "Webmail Fedora - smtp and pop3" application smtp
set vsys vsys1 rulebase security rules "Webmail Fedora - smtp and pop3" application pop3
set vsys vsys1 rulebase security rules "Webmail Fedora - smtp and pop3" service application-default
set vsys vsys1 rulebase security rules "Webmail Fedora - smtp and pop3" action allow
set vsys vsys1 rulebase security rules "Webmail Fedora - smtp and pop3" log-start yes

# --- Rule 3: Splunk - IN ---
set vsys vsys1 rulebase security rules "Splunk - IN" from any
set vsys vsys1 rulebase security rules "Splunk - IN" to internal
set vsys vsys1 rulebase security rules "Splunk - IN" source any
set vsys vsys1 rulebase security rules "Splunk - IN" destination 172.25.25.9
set vsys vsys1 rulebase security rules "Splunk - IN" application splunk
set vsys vsys1 rulebase security rules "Splunk - IN" service application-default
set vsys vsys1 rulebase security rules "Splunk - IN" action allow
set vsys vsys1 rulebase security rules "Splunk - IN" log-start yes

# --- Rule 4: internal - out ---
set vsys vsys1 rulebase security rules "internal - out" from internal
set vsys vsys1 rulebase security rules "internal - out" to external
set vsys vsys1 rulebase security rules "internal - out" source any
set vsys vsys1 rulebase security rules "internal - out" destination any
set vsys vsys1 rulebase security rules "internal - out" application any
set vsys vsys1 rulebase security rules "internal - out" service application-default
set vsys vsys1 rulebase security rules "internal - out" action allow
set vsys vsys1 rulebase security rules "internal - out" log-start yes

# --- Rule 5: any to any (disabled) ---
set vsys vsys1 rulebase security rules "any to any" from external
set vsys vsys1 rulebase security rules "any to any" to any
set vsys vsys1 rulebase security rules "any to any" source any
set vsys vsys1 rulebase security rules "any to any" destination any
set vsys vsys1 rulebase security rules "any to any" application any
set vsys vsys1 rulebase security rules "any to any" service application-default
set vsys vsys1 rulebase security rules "any to any" action allow
set vsys vsys1 rulebase security rules "any to any" disabled yes

# --- Rule 6: drop external - in ---
set vsys vsys1 rulebase security rules "drop external - in" from external
set vsys vsys1 rulebase security rules "drop external - in" to internal
set vsys vsys1 rulebase security rules "drop external - in" source any
set vsys vsys1 rulebase security rules "drop external - in" destination any
set vsys vsys1 rulebase security rules "drop external - in" application any
set vsys vsys1 rulebase security rules "drop external - in" service application-default
set vsys vsys1 rulebase security rules "drop external - in" action drop
set vsys vsys1 rulebase security rules "drop external - in" log-start yes

# --- Validate + Commit ---
validate
commit

exit

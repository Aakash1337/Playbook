#!/bin/bash

SPLUNK_HOME="/opt/splunk"
REPORT="splunk_hardening_report.txt"

# --- CONFIGURATION: Add your authorized app folder names here ---
KNOWN_APPS=(
    "alert_logevent" "audit_trail" "search" "launcher" "learned" "framework" "gettingstarted" 
    "alert_webhook" "appsbrowser" "introspection_generator" 
    "splunk_archiver" "splunk_monitoring_console" "splunk_httpinput"
    "splunk_instrumentation" "splunk_internal_metrics" "splunk_mgreq_handler"
    "splunk_rapid_diag" "splunk_secure_gateway" "splunk_ihc" "cyber_security_essentials_avert" "introspection_generator_addon" "journald_input" "legacy" "python_upgrade_readiness_app" "splunk_app_for_splunk_o11y_cloud" "splunk-dashboard-studio" "splunk-data-management" "SplunkDeploymentServerConfig" "SplunkForwarder" "splunk_gdi" "SplunkLightForwarder" "splunk_metrics_workspace" "splunk_pipeline_builders" "splunk-rolling-upgrade" "splunk-visual-exporter" "user-prefs"
)

echo "Starting Splunk Security Audit..."
echo "Report generated on: $(date)" > "$REPORT"
echo "==========================================================" >> "$REPORT"

# 1. GET ALL USERS FROM passwd (Corrected for leading colon)
echo -e "\n[!] LOCAL SPLUNK USERS (from etc/passwd):" >> "$REPORT"

if [ -f "$SPLUNK_HOME/etc/passwd" ]; then
    # We use -f2 because the lines start with a delimiter
    cut -d: -f2 "$SPLUNK_HOME/etc/passwd" >> "$REPORT"
else
    echo "ERROR: passwd file not found!" >> "$REPORT"
fi

# 2. GET ALL USER FOLDERS IN etc/users
echo -e "\n[!] USER DIRECTORIES (from etc/users):" >> "$REPORT"
if [ -d "$SPLUNK_HOME/etc/users" ]; then
    ls -1 "$SPLUNK_HOME/etc/users" >> "$REPORT"
else
    echo "No user directories found." >> "$REPORT"
fi

# 3. APP COMPARISON
echo -e "\n[!] UNAUTHORIZED / UNKNOWN APPS:" >> "$REPORT"
FOUND_SUSPICIOUS=0

# Loop through every folder in etc/apps
for app_path in "$SPLUNK_HOME"/etc/apps/*; do
    app_name=$(basename "$app_path")
    
    # Check if app_name is in our KNOWN_APPS array
    is_known=false
    for known in "${KNOWN_APPS[@]}"; do
        if [[ "$app_name" == "$known" ]]; then
            is_known=true
            break
        fi
    done

    # If not known, flag it
    if [ "$is_known" = false ]; then
        echo "SUSPICIOUS APP FOUND: $app_name" >> "$REPORT"
        
        # Check if it has a bin directory (high risk)
        if [ -d "$app_path/bin" ]; then
            echo "   -> WARNING: This app contains an executable /bin directory." >> "$REPORT"
        fi
        
        # Check if it has a scripted input
        if grep -q "\[script://" "$app_path/local/inputs.conf" 2>/dev/null; then
            echo "   -> WARNING: This app has a scripted input (Potential persistence)." >> "$REPORT"
        fi
        
        FOUND_SUSPICIOUS=1
    fi
done

# 4. WEB SHELL & STATIC ASSET AUDIT
echo -e "\n[!] SCANNING FOR POTENTIAL WEB SHELLS:" >> "$REPORT"

# Search for Python or Shell scripts in static web directories
# We look for files modified in the last 30 days as a priority
WEB_PATHS=(
    "$SPLUNK_HOME/share/splunk/search_mrsparkle/exposed"
    "$SPLUNK_HOME/etc/apps/*/appserver/static"
)

for path in "${WEB_PATHS[@]}"; do
    # Find scripts in web-accessible folders
    SHELLS=$(find $path -type f \( -name "*.py" -o -name "*.sh" -o -name "*.php" \) 2>/dev/null)
    if [ ! -z "$SHELLS" ]; then
        echo "WARNING: Potential Web Shell/Script found in web-accessible path:" >> "$REPORT"
        echo "$SHELLS" >> "$REPORT"
    fi
done

if [ $FOUND_SUSPICIOUS -eq 0 ]; then
    echo "No unknown apps detected based on your whitelist." >> "$REPORT"
fi

echo "==========================================================" >> "$REPORT"
echo "Audit Complete. Review $REPORT for results."

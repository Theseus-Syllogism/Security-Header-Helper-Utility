#!/bin/bash

# ANSI color codes
RED='\033[31m'
GREEN='\033[32m'
BLUE='\033[34m'
YELLOW='\033[33m'
NC='\033[0m' # No Color

detect_distro() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
        return 0
    fi

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" == "debian" || "$ID" == "ubuntu" || "$ID_LIKE" == *"debian"* ]]; then
            echo "debian"
        elif [[ "$ID" == "fedora" || "$ID_LIKE" == *"fedora"* ]]; then
            echo "fedora"
        elif [[ "$ID" == "arch" || "$ID_LIKE" == *"arch"* ]]; then
            echo "arch"
        else
            echo "unknown"
        fi
    else
        echo "unknown"
    fi
}

install_tools() {
    echo -e "${BLUE}Checking for Node.js, npm, jq, figlet, git, nuclei, and retire...${NC}"
    distro=$(detect_distro)

    if ! command -v node &> /dev/null || ! command -v npm &> /dev/null || ! command -v jq &> /dev/null || ! command -v figlet &> /dev/null || ! command -v git &> /dev/null || ! command -v nuclei &> /dev/null; then
        echo -e "${YELLOW}Installing Node.js, npm, jq, figlet, git, and nuclei for $distro...${NC}"
        case "$distro" in
            debian)
                sudo apt-get update
                sudo apt-get install -y nodejs npm jq figlet git
                # Install nuclei
                wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_Linux_amd64.zip
                unzip nuclei_Linux_amd64.zip
                sudo mv nuclei /usr/local/bin/
                rm nuclei_Linux_amd64.zip
                ;;
            fedora)
                sudo dnf install -y nodejs npm jq figlet git
                # Install nuclei
                wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_Linux_amd64.zip
                unzip nuclei_Linux_amd64.zip
                sudo mv nuclei /usr/local/bin/
                rm nuclei_Linux_amd64.zip
                ;;
            arch)
                echo -e "${YELLOW}Arch Linux detected. Installing packages without full system upgrade to avoid dependency conflicts.${NC}"
                echo -e "${YELLOW}If installation fails, resolve conflicts manually with 'pacman -Syu' and retry.${NC}"
                sudo pacman -S --needed nodejs npm jq figlet git nuclei
                if [[ $? -ne 0 ]]; then
                    echo -e "${RED}Error: Pacman failed to install packages. Please resolve dependency conflicts manually (e.g., 'sudo pacman -Syu') and rerun the script.${NC}"
                    exit 1
                fi
                ;;
            macos)
                brew install node jq figlet git nuclei
                ;;
            *)
                echo -e "${RED}Unsupported OS for automatic installation. Please install nodejs, npm, jq, figlet, git, and nuclei manually.${NC}"
                exit 1
                ;;
        esac
    fi

    echo -e "${YELLOW}Updating nuclei templates...${NC}"
    if ! nuclei -update-templates >/dev/null 2>&1; then
        echo -e "${YELLOW}Warning: Failed to update nuclei templates. Ensure internet connectivity and try 'nuclei -update-templates' manually.${NC}"
    fi

    NPM_GLOBAL_DIR="$HOME/.npm-global"
    mkdir -p "$NPM_GLOBAL_DIR"
    npm config set prefix "$NPM_GLOBAL_DIR"
    export PATH="$NPM_GLOBAL_DIR/bin:$PATH"

    echo -e "${YELLOW}Installing retire.js locally...${NC}"
    if ! command -v retire &> /dev/null; then
        npm install --prefix "$NPM_GLOBAL_DIR" retire
        if [[ $? -ne 0 ]]; then
            echo -e "${RED}Error: Failed to install retire.js. Check npm logs in ~/.npm/_logs/ for details.${NC}"
            exit 1
        fi
    fi
}

display_csp_title() {
    if command -v figlet &> /dev/null; then
        figlet -f standard "CSP Header"
    else
        echo -e "${BLUE}========================================${NC}"
        echo -e "${BLUE}         CSP Header${NC}"
        echo -e "${BLUE}========================================${NC}"
    fi
}


usage() {
    echo -e "${RED}Usage: $0 [-u <url>] [-f <file>] [--url <url>] [-m <url>]${NC}"
    echo "  -u <url>     : URL of the website to check for CSP (e.g., https://example.com)"
    echo "  -f <file>    : Optional configuration file to inject CSP headers"
    echo "  --url <url>  : URL to scan for JavaScript libraries and vulnerabilities using retire and nuclei"
    echo "  -m <url>     : Make missing security headers (excluding CSP) for the specified URL"
    exit 1
}

validate_url() {
    local url=$1
    if [[ ! $url =~ ^https?:// ]]; then
        echo -e "${RED}Error: Invalid URL format. Please provide a valid URL (e.g., https://example.com)${NC}"
        exit 1
    fi
}

check_csp() {
    local url=$1
    echo -e "${BLUE}Checking CSP for $url...${NC}"
    response=$(curl -s -I "$url")
    csp_header=$(echo "$response" | awk -v RS='\r\n\r\n' '/^[Cc]ontent-[Ss]ecurity-[Pp]olicy:/ {gsub(/^[Cc]ontent-[Ss]ecurity-[Pp]olicy: */, ""); print}' | tr -d '\r' | tr '\n' ' ')
    if [[ -n "$csp_header" ]]; then
        echo -e "${GREEN}CSP is enabled for $url${NC}"

        echo -e "${YELLOW}CSP Header:${NC}\nContent-Security-Policy:\n$csp_header"

        return 0
    else
        echo -e "${RED}CSP is not enabled for $url${NC}"
        return 1
    fi
}

check_missing_headers() {
    local url=$1
    echo -e "${BLUE}Checking missing security headers for $url...${NC}"
    response=$(curl -s -I "$url" | grep -i "Strict-Transport-Security|X-Frame-Options|X-Content-Type-Options|Referrer-Policy|Permissions-Policy|Cross-Origin-Opener-Policy|Cross-Origin-Embedder-Policy|Cross-Origin-Resource-Policy")
    missing_headers=()

    if ! echo "$response" | grep -i "Strict-Transport-Security" > /dev/null; then
        echo -e "${YELLOW}Warning: Adding Strict-Transport-Security will force all domains to use HTTPS, which may break configurations using only HTTP (port 80).${NC}"
        read -p "Add Strict-Transport-Security header? (y/n): " confirm_hsts
        if [[ "$confirm_hsts" =~ ^[Yy] ]]; then
            missing_headers+=("Strict-Transport-Security: max-age=63072000; includeSubDomains; preload")
        fi
    fi
    if ! echo "$response" | grep -i "X-Frame-Options" > /dev/null; then
        missing_headers+=("X-Frame-Options: SAMEORIGIN")
    fi
    if ! echo "$response" | grep -i "X-Content-Type-Options" > /dev/null; then
        missing_headers+=("X-Content-Type-Options: nosniff")
    fi
    if ! echo "$response" | grep -i "Referrer-Policy" > /dev/null; then
        missing_headers+=("Referrer-Policy: strict-origin-when-cross-origin")
    fi
    if ! echo "$response" | grep -i "Permissions-Policy" > /dev/null; then
        missing_headers+=("Permissions-Policy: geolocation=(), microphone=(), camera=())")
    fi
    if ! echo "$response" | grep -i "Cross-Origin-Opener-Policy" > /dev/null; then
        missing_headers+=("Cross-Origin-Opener-Policy: same-origin")
    fi
    if ! echo "$response" | grep -i "Cross-Origin-Embedder-Policy" > /dev/null; then
        missing_headers+=("Cross-Origin-Embedder-Policy: require-corp")
    fi
    if ! echo "$response" | grep -i "Cross-Origin-Resource-Policy" > /dev/null; then
        missing_headers+=("Cross-Origin-Resource-Policy: same-origin")
    fi

    if [ ${#missing_headers[@]} -gt 0 ]; then
        echo -e "${YELLOW}Missing security headers detected:${NC}"
        for header in "${missing_headers[@]}"; do
            echo -e "  - $header"
        done

        # Generate Nginx missing headers file
        nginx_missing_conf="nginx-missing-headers.conf"
        cat > "$nginx_missing_conf" << EOF
# Nginx missing security headers
$(for header in "${missing_headers[@]}"; do
  echo "add_header $header always;"
done)
EOF
        echo -e "${GREEN}Nginx missing headers configuration saved to $nginx_missing_conf${NC}"

        # Generate Apache missing headers file
        apache_missing_conf="apache-missing-headers.conf"
        cat > "$apache_missing_conf" << EOF
# Apache missing security headers
<IfModule mod_headers.c>
$(for header in "${missing_headers[@]}"; do
  echo "    Header set $header"
done)
</IfModule>
EOF
        echo -e "${GREEN}Apache missing headers configuration saved to $apache_missing_conf${NC}"
    else
        echo -e "${GREEN}All security headers are present.${NC}"
    fi
}

check_csp() {
    local url=$1
    echo -e "${BLUE}Checking CSP for $url...${NC}"
    response=$(curl -s -I "$url")
    if echo "$response" | grep -i "Content-Security-Policy" > /dev/null; then
        echo -e "${GREEN}CSP is enabled for $url${NC}"
        echo -e "${YELLOW}CSP Header:${NC} $(echo "$response" | grep -i "Content-Security-Policy" | awk '{$1=$1};1')" #this needs to be fixed to output the actual CSP
        return 0
    else
        echo -e "${RED}CSP is not enabled for $url${NC}"
        return 1
    fi
}

infer_libraries_from_cdn() {
    local src=$1
    declare -A cdn_libraries=(
        ["code.jquery.com"]="jQuery"
        ["ajax.googleapis.com"]="jQuery jQuery Mobile"
        ["cdnjs.cloudflare.com"]="Various Popper.js"
        ["cdn.jsdelivr.net"]="Bootstrap Lodash Moment.js"
        ["unpkg.com"]="React Vue.js"
    )
    
    for cdn in "${!cdn_libraries[@]}"; do
        if [[ "$src" =~ $cdn ]]; then
            echo "${cdn_libraries[$cdn]}"
        fi
    done
}

get_js_libraries() {
    local url=$1
    echo -e "${BLUE}Fetching page content to identify JavaScript libraries...${NC}"
    page_content=$(curl -s "$url")
    
    # Extract all script sources
    script_sources=($(echo "$page_content" | grep -oE '<script[^>]+src=["'"'"'][^"'"'"']*["'"'"']' | sed 's/.*src=["'"'"']//;s/["'"'"'].*//' | sort -u))
    
    js_sources=()
    js_libraries=()
    
    # Resolve relative URLs and collect domains
    for src in "${script_sources[@]}"; do
        if [[ ! "$src" =~ ^https?:// ]]; then
            base_url=$(echo "$url" | grep -oE '^https?://[^/]+')
            if [[ "$src" =~ ^/ ]]; then
                src="${base_url}${src}"
            else
                src="${base_url}/${src}"
            fi
        fi
        js_sources+=("$src")
    done
    
    echo -e "${YELLOW}Scanning with nuclei...${NC}"
    nuclei_output_file=$(mktemp)
    nuclei_error_log="nuclei_error.log"
    nuclei -u "$url" -t http/technologies/missing-sri.yaml -json -silent > "$nuclei_output_file" 2>>"$nuclei_error_log"
    if [[ -s "$nuclei_output_file" ]]; then
        while IFS= read -r line; do
            if echo "$line" | jq -e . >/dev/null 2>&1; then
                sources=$(echo "$line" | jq -r '.info.metadata.resources[] // []')
                for src in $sources; do
                    if [[ "$src" =~ \.js$ ]]; then
                        js_sources+=("$src")
                        inferred_libs=$(infer_libraries_from_cdn "$src")
                        if [[ -n "$inferred_libs" ]]; then
                            for lib in $inferred_libs; do
                                js_libraries+=("$lib")
                            done
                        fi
                    fi
                done
            else
                echo -e "${YELLOW}Skipping invalid JSON line from nuclei output: $line${NC}" >> "$nuclei_error_log"
            fi
        done < "$nuclei_output_file"
    else
        echo -e "${YELLOW}No nuclei output. Ensure 'http/technologies/missing-sri.yaml' template is available (run 'nuclei -update-templates'). Check $nuclei_error_log for details.${NC}"
    fi
    rm -f "$nuclei_output_file"
    
    echo -e "${YELLOW}Scanning with retire...${NC}"
    retire_output=$("$HOME/.npm-global/bin/retire" --node --outputformat json --js "$url" 2>/dev/null)
    
    if [[ -n "$retire_output" ]]; then
        while IFS= read -r line; do
            if echo "$line" | jq -e '.data[].component' > /dev/null 2>&1; then
                component=$(echo "$line" | jq -r '.data[].component')
                version=$(echo "$line" | jq -r '.data[].version')
                js_libraries+=("$component $version")
            fi
        done < <(echo "$retire_output" | jq -c '.[]')
    else
        echo -e "${YELLOW}Retire scan failed. Ensure network connectivity and try updating retire signatures with 'npm update retire' in ~/.npm-global.${NC}"
    fi
    

    declare -A libraries=(
        ["jQuery"]="jquery|jQuery"
        ["React"]="react|React"
        ["Vue.js"]="vue|Vue"
        ["Angular"]="angular|Angular"
        ["Bootstrap"]="bootstrap"
        ["Lodash"]="lodash"
        ["Moment.js"]="moment"
        ["Backbone.js"]="backbone|Backbone"
        ["Ember.js"]="ember|Ember"
        ["Knockout.js"]="knockout|Knockout"
        ["Underscore.js"]="underscore|Underscore"
        ["D3"]="d3"
        ["Chart.js"]="chart\.js|Chart"
        ["Handlebars"]="handlebars|Handlebars"
        ["jQuery Mobile"]="jquery\.mobile|jQuery Mobile"
        ["Popper.js"]="popper|Popper"
    )
    
    for lib in "${!libraries[@]}"; do
        if echo "$page_content" | grep -i "${libraries[$lib]}" > /dev/null; then
            js_libraries+=("$lib")
        fi
    done
    
    # Remove duplicates
    js_libraries=($(printf "%s\n" "${js_libraries[@]}" | sort -u))
    js_sources=($(printf "%s\n" "${js_sources[@]}" | sort -u))
    
    if [ ${#js_libraries[@]} -eq 0 ]; then
        echo -e "${YELLOW}No JavaScript libraries detected by nuclei, retire, regex, or CDN inference.${NC}"
    else
        echo -e "${GREEN}Detected JavaScript libraries:${NC}"
        for lib in "${js_libraries[@]}"; do
            echo -e "  - $lib"
        done
    fi
    
    echo -e "${GREEN}Detected script sources:${NC}"
    for src in "${js_sources[@]}"; do
        echo -e "  - $src"
    done
}

#Retire -> Fix and output vulnerabilities later
scan_with_retire() {
    local url=$1
    echo -e "${BLUE}Scanning $url for JavaScript library vulnerabilities using retire...${NC}"
    retire_output=$("$HOME/.npm-global/bin/retire" --node --outputformat json --js "$url" 2>/dev/null)
    
    if [[ -z "$retire_output" ]]; then
        echo -e "${YELLOW}No vulnerabilities found or retire scan failed. Ensure network connectivity and try updating retire signatures with 'npm update retire' in ~/.npm-global.${NC}"
        return
    fi
    
    libraries=()
    cves=()
    while IFS= read -r line; do
        if echo "$line" | jq -e '.data[].component' > /dev/null 2>&1; then
            component=$(echo "$line" | jq -r '.data[].component')
            version=$(echo "$line" | jq -r '.data[].version')
            libraries+=("$component $version")
        fi
        if echo "$line" | jq -e '.data[].vulnerabilities' > /dev/null 2>&1; then
            vuln=$(echo "$line" | jq -r '.data[].vulnerabilities[] | .identifiers.CVE? // empty')
            if [[ -n "$vuln" ]]; then
                cves+=("$vuln")
            fi
        fi
    done < <(echo "$retire_output" | jq -c '.[]')
    
    echo -e "\n${GREEN}Libraries:${NC}"
    if [ ${#libraries[@]} -eq 0 ]; then
        echo -e "  ${YELLOW}None detected.${NC}"
    else
        for lib in "${libraries[@]}"; do
            echo -e "  - $lib"
        done
    fi
    
    echo -e "\n${GREEN}Libraries CVEs:${NC}"
    if [ ${#cves[@]} -eq 0 ]; then
        echo -e "  ${YELLOW}None detected.${NC}"
    else
        for cve in "${cves[@]}"; do
            echo -e "  - $cve"
        done
    fi
    
    echo -e "\n${BLUE}Nginx CSP Headers (including library sources):${NC}"
    csp="default-src 'self';\n  script-src 'self'"
    unique_domains=($(printf "%s\n" "${js_sources[@]}" | grep -oE 'https?://[^/]+' | sort -u))
    for domain in "${unique_domains[@]}"; do
        csp="$csp $domain"
    done
    csp="$csp 'unsafe-inline';\n  style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline';\n  img-src 'self' data:;\n  media-src 'self';\n  object-src 'self';\n  frame-src 'self';\n  connect-src 'self';\n  base-uri 'none';\n  form-action 'self';\n  frame-ancestors 'self';\n  upgrade-insecure-requests;"
    echo -e "${BLUE}Nginx:${NC}\nadd_header Content-Security-Policy \"$csp\";"
    echo -e "${BLUE}Apache:${NC}\nHeader set Content-Security-Policy \"$csp\""
    
    verify_headers "$url" "$csp"
}

generate_csp_header() {
    local js_sources=("$@")
    csp="default-src 'self';\n  script-src 'self'"
    
    unique_domains=($(printf "%s\n" "${js_sources[@]}" | grep -oE 'https?://[^/]+' | sort -u))
    for domain in "${unique_domains[@]}"; do
        csp="$csp $domain"
    done
    csp="$csp 'unsafe-inline';\n  style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline';\n  img-src 'self' data:;\n  media-src 'self';\n  object-src 'self';\n  frame-src 'self';\n  connect-src 'self';\n  base-uri 'none';\n  form-action 'self';\n  frame-ancestors 'self';\n  upgrade-insecure-requests;"
    
    echo -e "${BLUE}"
    display_csp_title
    echo -e "${GREEN}Generated CSP Header:${NC}\n$csp"
    
    # Output Nginx configuration file
    nginx_conf="nginx-csp.conf"
    cat > "$nginx_conf" << EOF
# Nginx configuration with CSP header
add_header Content-Security-Policy "$csp";
EOF
    echo -e "${GREEN}Nginx configuration saved to $nginx_conf${NC}"
    
    # Output Apache configuration file
    apache_conf="apache-csp.conf"
    cat > "$apache_conf" << EOF
# Apache configuration with CSP header
<IfModule mod_headers.c>
    Header set Content-Security-Policy "$csp"
</IfModule>
EOF
    echo -e "${GREEN}Apache configuration saved to $apache_conf${NC}"
}

inject_csp_header() {
    local config_file=$1
    local csp=$2
    local server_type=$3
    
    if [[ ! -f "$config_file" ]]; then
        echo -e "${RED}Error: Configuration file $config_file does not exist.${NC}"
        return 1
    fi
    
    backup_file="${config_file}.backup_$(date +%F_%T)"
    cp "$config_file" "$backup_file"
    echo -e "${GREEN}Backed up $config_file to $backup_file${NC}"
    
    if [[ "$server_type" == "nginx" ]]; then
        if grep -i "Content-Security-Policy" "$config_file" > /dev/null; then
            echo -e "${YELLOW}Existing CSP header found in $config_file. Replacing it...${NC}"
            sed -i "/add_header Content-Security-Policy/d" "$config_file"
        fi
        sed -i "/server {/a \    add_header Content-Security-Policy \"$csp\";" "$config_file"
        echo -e "${GREEN}Injected Nginx CSP header into $config_file${NC}"
    elif [[ "$server_type" == "apache" ]]; then
        if grep -i "Content-Security-Policy" "$config_file" > /dev/null; then
            echo -e "${YELLOW}Existing CSP header found in $config_file. Replacing it...${NC}"
            sed -i "/Header set Content-Security-Policy/d" "$config_file"
        fi
        echo -e "\n<IfModule mod_headers.c>\n    Header set Content-Security-Policy \"$csp\"\n</IfModule>" >> "$config_file"
        echo -e "${GREEN}Injected Apache CSP header into $config_file${NC}"
    else
        echo -e "${RED}Error: Unsupported server type.${NC}"
        return 1
    fi
}

# Main script
url=""
config_file=""
retire_url=""
missing_headers_url=""
while getopts "u:f:m:-:" opt; do
    case $opt in
        u) url="$OPTARG";;
        f) config_file="$OPTARG";;
        m) missing_headers_url="$OPTARG";;
        -)
            case "${OPTARG}" in
                url)
                    retire_url="${!OPTIND}"
                    OPTIND=$(( OPTIND + 1 ));;
                *) echo -e "${RED}Unknown option --${OPTARG}${NC}"; usage;;
            esac;;
        *) usage;;
    esac
done

# Install tools
install_tools

# Validate inputs
if [[ -z "$url" && -z "$config_file" && -z "$retire_url" && -z "$missing_headers_url" ]]; then
    echo -e "${RED}Please provide a URL, configuration file, or retire URL.${NC}"
    usage
fi

if [[ -n "$url" ]]; then
    validate_url "$url"
    if ! check_csp "$url"; then
        get_js_libraries "$url"
        if [ ${#js_sources[@]} -gt 0 ]; then
            generate_csp_header "${js_sources[@]}"
        else
            echo -e "${YELLOW}No JavaScript libraries detected, using default CSP.${NC}"
            generate_csp_header
        fi
    fi
fi

if [[ -n "$retire_url" ]]; then
    validate_url "$retire_url"
    get_js_libraries "$retire_url"
    scan_with_retire "$retire_url"
    if [ ${#js_sources[@]} -gt 0 ]; then
        generate_csp_header "${js_sources[@]}"
    else
        echo -e "${YELLOW}No JavaScript libraries detected, using default CSP.${NC}"
        generate_csp_header
    fi
fi

if [[ -n "$missing_headers_url" ]]; then
    validate_url "$missing_headers_url"
    check_missing_headers "$missing_headers_url"
fi

if [[ -n "$config_file" ]]; then
    echo -e "${BLUE}Configuration file provided: $config_file${NC}"
    read -p "Is this an Nginx or Apache configuration file? (nginx/apache): " server_type
    if [[ "$server_type" != "nginx" && "$server_type" != "apache" ]]; then
        echo -e "${RED}Error: Please specify 'nginx' or 'apache'.${NC}"
        exit 1
    fi
    
    if [[ -z "$csp" && (-n "$url" || -n "$retire_url") ]]; then
        if [ ${#js_sources[@]} -gt 0 ]; then
            unique_domains=($(printf "%s\n" "${js_sources[@]}" | grep -oE 'https?://[^/]+' | sort -u))
            csp="default-src 'self';\n  script-src 'self' ${unique_domains[*]} 'unsafe-inline';\n  style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline';\n  img-src 'self' data:;\n  media-src 'self';\n  object-src 'self';\n  frame-src 'self';\n  connect-src 'self';\n  base-uri 'none';\n  form-action 'self';\n  frame-ancestors 'self';\n  upgrade-insecure-requests;"
        else
            csp="default-src 'self';\n  script-src 'self' 'unsafe-inline';\n  style-src 'self' 'unsafe-inline';\n  img-src 'self' data:;\n  media-src 'self';\n  object-src 'self';\n  frame-src 'self';\n  connect-src 'self';\n  base-uri 'none';\n  form-action 'self';\n  frame-ancestors 'self';\n  upgrade-insecure-requests;"
        fi
    elif [[ -z "$csp" ]]; then
        csp="default-src 'self';\n  script-src 'self' 'unsafe-inline';\n  style-src 'self' 'unsafe-inline';\n  img-src 'self' data:;\n  media-src 'self';\n  object-src 'self';\n  frame-src 'self';\n  connect-src 'self';\n  base-uri 'none';\n  form-action 'self';\n  frame-ancestors 'self';\n  upgrade-insecure-requests;"
    fi
    
    inject_csp_header "$config_file" "$csp" "$server_type"
fi
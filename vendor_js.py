import urllib.request
import re
import os

BASE_URL = "https://esm.sh"
STATIC_DIR = "ledger/static"

def download_and_rewrite(url, filename):
    print(f"Downloading {url} to {filename}...")
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'})
    with urllib.request.urlopen(req) as response:
        content = response.read().decode('utf-8')
    
    # Find all imports like: import {sha512 as o} from"/v135/@noble/hashes@1.3.1/es2022/sha512.bundle.mjs";
    imports = re.findall(r'from\s*["\'](/[^"\']+)["\']', content)
    imports += re.findall(r'import\s*["\'](/[^"\']+)["\']', content)
    imports += re.findall(r'export\s*\*\s*from\s*["\'](/[^"\']+)["\']', content)
    
    for imp in imports:
        # e.g., imp = "/v135/@noble/hashes@1.3.1/es2022/sha512.bundle.mjs"
        dep_url = BASE_URL + imp
        dep_filename = imp.split('/')[-1]
        
        # Rewrite the import in the content to point to the local file
        content = content.replace(f'"{imp}"', f'"./{dep_filename}"')
        content = content.replace(f"'{imp}'", f"'./{dep_filename}'")
        
        # Download the dependency recursively if not already downloaded
        dep_path = os.path.join(STATIC_DIR, dep_filename)
        if not os.path.exists(dep_path):
            download_and_rewrite(dep_url, dep_filename)
            
    with open(os.path.join(STATIC_DIR, filename), "w") as f:
        f.write(content)

if __name__ == "__main__":
    os.makedirs(STATIC_DIR, exist_ok=True)
    download_and_rewrite("https://esm.sh/@noble/ed25519@2.0.0?target=es2022", "ed25519.js")
    download_and_rewrite("https://esm.sh/@noble/hashes@1.3.1/sha512?target=es2022", "sha512.js")
    download_and_rewrite("https://esm.sh/@noble/hashes@1.3.1/sha256?target=es2022", "sha256.js")
    print("Vendoring complete.")

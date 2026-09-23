import asyncio
import aiohttp
from app.scanner.hacktheweb_adapter import load_hacktheweb_components

async def main():
    components = load_hacktheweb_components()
    Config = components["Config"]
    cfg = Config()
    scanner_names = [
        "SecurityHeadersScanner", "CSRFScanner", "CORSScanner", "XSSScanner", "SQLiScanner",
        "SSRFScanner", "LFIScanner", "XXEScanner", "RCEScanner", "IDORScanner",
        "OpenRedirectScanner", "PathTraversalScanner", "NoSQLiScanner", "LDAPIScanner", "SSTIScanner"
    ]
    
    async with aiohttp.ClientSession() as session:
        for name in scanner_names:
            try:
                cls = components[name]
                scanner = cls(cfg, session)
                print(f"Testing {name}...", end=" ")
                # Just see if we can call scan. Most will fail gracefully if recon_data is empty.
                await scanner.scan("http://example.com", {"url": "http://example.com", "inputs": [], "forms": [], "links": []})
                print("OK")
            except Exception as e:
                print(f"FAILED: {type(e).__name__} - {e}")

if __name__ == "__main__":
    asyncio.run(main())

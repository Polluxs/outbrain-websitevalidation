import asyncio
import gc
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
from camoufox.async_api import AsyncCamoufox
from dotenv import load_dotenv
import os

# Expected parameters in Outbrain Multivac calls (from your research)
EXPECTED_PARAMS = {
    # Identification & Linking
    'widgetJSId', 'idx', 'rand', 'clid',
    # Position & Visibility
    'px', 'py', 'vpd', 'winW', 'winH', 'scrW', 'scrH', 'dpr',
    # Network & Performance
    'ttfb', 'bandwidth', 'netQ',
    # Client Hints (Fingerprinting)
    'cha', 'chb', 'chp', 'chpv', 'chfv',
    # Consent
    'ccnsnt', 'cmpStat', 'ccpaStat',
    # Other
    'url', 'format', 'settings', 'recs', 'version', 'clientType', 'clientVer',
    'secured', 'activeTab', 'tch', 'adblck', 'ogn', 'sig'
}


def get_db_connection():
    """Get database connection"""
    return psycopg2.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        port=os.getenv('DB_PORT', '5432'),
        database=os.getenv('DB_NAME'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD')
    )


def fetch_unprocessed_domains(limit=1000):
    """Fetch domains that haven't been checked yet"""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, name_text
                FROM domain
                WHERE outbrain_status IS NULL
                ORDER BY id
                LIMIT %s
            """, (limit,))
            return cur.fetchall()
    finally:
        conn.close()


def update_domain_status(domain_id, status, partial_params=None):
    """Update domain with validation results"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE domain
                SET outbrain_status      = %s,
                    partial_params_found = %s,
                    checked_timestamp    = %s
                WHERE id = %s
            """, (status, partial_params, datetime.now(), domain_id))
            conn.commit()
    finally:
        conn.close()


def analyze_outbrain_requests(outbrain_requests):
    """Analyze captured Outbrain requests for parameters"""
    if not outbrain_requests:
        return 'not_using_outbrain', None

    # Look for Multivac API calls
    multivac_calls = [r for r in outbrain_requests if 'mv.outbrain.com/Multivac/api/get' in r]

    if not multivac_calls:
        # Outbrain is present but no Multivac call - still using Outbrain
        return 'using_outbrain_all_params', None

    # Parse parameters from first Multivac call
    parsed = urlparse(multivac_calls[0])
    params = parse_qs(parsed.query)
    found_params = set(params.keys())

    # Check if all expected params are present
    missing_params = EXPECTED_PARAMS - found_params
    extra_params = found_params - EXPECTED_PARAMS

    if not missing_params:
        # All expected parameters found
        return 'using_outbrain_all_params', None
    else:
        # Some parameters missing - this is weird
        result = {
            'found': sorted(list(found_params)),
            'missing': sorted(list(missing_params)),
            'extra': sorted(list(extra_params)) if extra_params else []
        }
        return 'using_outbrain_partial_params', str(result)


async def validate_domain(domain_name, page):
    """Validate a single domain"""
    outbrain_requests = []

    def handle_request(request):
        """Capture all network requests"""
        url = request.url
        if 'outbrain.com' in url:
            outbrain_requests.append(url)

    # Ensure domain has protocol
    if not domain_name.startswith('http'):
        url = f'https://{domain_name}'
    else:
        url = domain_name

    print(f"Checking: {url}")

    try:
        # Listen to network requests
        page.on('request', handle_request)

        # Navigate with 30s timeout
        await page.goto(url, wait_until="load", timeout=30000)

        # Wait a bit for dynamic content to load
        await asyncio.sleep(2)

        # Analyze results
        status, partial_params = analyze_outbrain_requests(outbrain_requests)

        print(f"  Result: {status}")
        if partial_params:
            print(f"  Partial params: {partial_params[:100]}...")

        return status, partial_params

    except asyncio.TimeoutError:
        print(f"  Timeout - marking as not_using_outbrain")
        return 'not_using_outbrain', None
    except Exception as e:
        print(f"  Error: {str(e)[:100]} - marking as not_using_outbrain")
        return 'not_using_outbrain', None


async def process_batch(domains, batch_size=10):
    """Process a batch of domains with browser recreation every 10"""
    total = len(domains)

    for i in range(0, total, batch_size):
        batch = domains[i:i + batch_size]
        print(f"\n=== Processing batch {i // batch_size + 1} ({i + 1}-{min(i + batch_size, total)} of {total}) ===")

        # Create browser for this batch
        async with AsyncCamoufox(headless=True) as browser:
            page = await browser.new_page()

            for domain in batch:
                status, partial_params = await validate_domain(domain['name_text'], page)
                update_domain_status(domain['id'], status, partial_params)

            await page.close()

        # Force garbage collection after browser closes
        gc.collect()
        print(f"=== Batch complete, browser cleaned up ===\n")


async def main():
    # Load environment variables from .env file
    load_dotenv()

    # Fetch unprocessed domains
    print("Fetching unprocessed domains...")
    domains = fetch_unprocessed_domains(limit=1000)

    if not domains:
        print("No unprocessed domains found!")
        return

    print(f"Found {len(domains)} unprocessed domains\n")

    # Process in batches of 10

    await process_batch(domains, batch_size=10)

    print("\n=== Validation complete! ===")


if __name__ == "__main__":
    asyncio.run(main())

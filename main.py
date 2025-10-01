import asyncio
import gc
import json
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
from camoufox.async_api import AsyncCamoufox
from dotenv import load_dotenv
import os
from src.logging_config import logger

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


def update_domain_status(domain_id, status, partial_params=None, har_data=None):
    """Update domain with validation results"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Convert har_data string to binary if present
            har_binary = har_data.encode('utf-8') if har_data else None

            cur.execute("""
                UPDATE domain
                SET outbrain_status      = %s,
                    partial_params_found = %s,
                    checked_timestamp    = %s,
                    har_file_bytea       = %s
                WHERE id = %s
            """, (status, partial_params, datetime.now(), har_binary, domain_id))
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


async def validate_domain(domain_name, page, cdp_session):
    """Validate a single domain"""
    outbrain_requests = []

    def handle_request(request):
        """Capture all network requests"""
        request_url = request.url
        if 'outbrain.com' in request_url:
            outbrain_requests.append(request_url)

    # Ensure domain has protocol
    if not domain_name.startswith('http'):
        url = f'https://{domain_name}'
    else:
        url = domain_name

    logger.info(f"Checking domain: {url}")

    try:
        # Listen to network requests
        page.on('request', handle_request)

        # Navigate with 30s timeout
        await page.goto(url, wait_until="load", timeout=30000)

        # Wait a bit for dynamic content to load
        await asyncio.sleep(2)

        # Analyze results
        status, partial_params = analyze_outbrain_requests(outbrain_requests)

        logger.info(f"Domain {url} - Status: {status}")
        if partial_params:
            logger.info(f"Partial params found: {partial_params[:100]}...")

        # Get HAR data only if Outbrain is present
        har_data = None
        if status != 'not_using_outbrain':
            try:
                har = await cdp_session.send('Network.getHAR')
                # Convert to JSON string exactly as browser would export it
                har_json = json.dumps(har, indent=2)
                har_size_mb = len(har_json.encode('utf-8')) / (1024 * 1024)

                if har_size_mb > 10:
                    logger.error(f"HAR file too large ({har_size_mb:.2f}MB) for {url}, skipping storage")
                    har_data = None
                else:
                    har_data = har_json
                    logger.info(f"HAR file captured ({har_size_mb:.2f}MB) for {url}")
            except Exception as e:
                logger.error(f"Failed to capture HAR for {url}: {str(e)}")

        return status, partial_params, har_data

    except asyncio.TimeoutError:
        logger.warning(f"Timeout for {url} - marking as not_using_outbrain")
        return 'not_using_outbrain', None, None
    except Exception as e:
        logger.error(f"Error validating {url}: {str(e)}")
        return 'not_using_outbrain', None, None


async def process_batch(domains, batch_size=10):
    """Process a batch of domains with browser recreation every 10"""
    total = len(domains)

    for i in range(0, total, batch_size):
        batch = domains[i:i + batch_size]
        logger.info(f"Processing batch {i // batch_size + 1} ({i + 1}-{min(i + batch_size, total)} of {total})")

        # Create browser for this batch
        async with AsyncCamoufox(headless=True) as browser:
            page = await browser.new_page()

            # Enable Network domain for HAR capture
            cdp_session = await page.context.new_cdp_session(page)
            await cdp_session.send('Network.enable')

            for domain in batch:
                status, partial_params, har_data = await validate_domain(domain['name_text'], page, cdp_session)
                update_domain_status(domain['id'], status, partial_params, har_data)

            await page.close()

        # Force garbage collection after browser closes
        gc.collect()
        logger.info("Batch complete, browser cleaned up")


async def main():
    # Load environment variables from .env file
    load_dotenv()

    # Fetch unprocessed domains
    logger.info("Fetching unprocessed domains...")
    domains = fetch_unprocessed_domains(limit=1000)

    if not domains:
        logger.info("No unprocessed domains found!")
        return

    logger.info(f"Found {len(domains)} unprocessed domains")

    # Process in batches of 10
    await process_batch(domains, batch_size=10)

    logger.info("Validation complete!")


if __name__ == "__main__":
    asyncio.run(main())

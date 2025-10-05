import asyncio
import gc
import gzip
import sys
import tempfile
import os
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
from camoufox.async_api import AsyncCamoufox
from dotenv import load_dotenv
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
            # Compress har_data if present (gzip compression for legal evidence preservation)
            har_binary = gzip.compress(har_data.encode('utf-8')) if har_data else None

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


async def validate_domain(domain_name, page):
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

        # Navigate with 30s timeout, wrapped in asyncio.wait_for for safety
        try:
            await asyncio.wait_for(
                page.goto(url, wait_until="load", timeout=30000),
                timeout=35.0  # Slightly longer than page timeout
            )
        except asyncio.TimeoutError:
            logger.warning(f"Navigation timeout for {url}")
            return 'not_using_outbrain', None

        # Wait a bit for dynamic content to load
        await asyncio.sleep(2)

        # Analyze results
        status, partial_params = analyze_outbrain_requests(outbrain_requests)

        logger.info(f"Domain {url} - Status: {status}")
        if partial_params:
            logger.info(f"Partial params found: {partial_params[:100]}...")

        return status, partial_params

    except Exception as e:
        logger.error(f"Error validating {url}: {str(e)}")
        return 'not_using_outbrain', None


async def process_batch(domains, batch_size=10):
    """Process a batch of domains with browser recreation every 10"""
    total = len(domains)

    for i in range(0, total, batch_size):
        batch = domains[i:i + batch_size]
        logger.info(f"Processing batch {i // batch_size + 1} ({i + 1}-{min(i + batch_size, total)} of {total})")

        # Clean up any leftover HAR files from previous crashes
        temp_dir = os.getenv('TEMP_DIR', '/tmp')
        try:
            har_files = [f for f in os.listdir(temp_dir) if f.endswith('.har')]
            if har_files:
                logger.info(f"Cleaning up {len(har_files)} leftover HAR files...")
                for har_file in har_files:
                    try:
                        os.remove(os.path.join(temp_dir, har_file))
                    except Exception as ex:
                        logger.warning(f"Could not remove {har_file}: {ex}")
        except Exception as ex:
            logger.warning(f"Could not clean temp directory: {ex}")

        # Create browser once per batch
        async with AsyncCamoufox(headless=True) as browser:
            for domain in batch:
                logger.info(f"Starting processing for {domain['name_text']}...")

                # Create HAR file path (don't use NamedTemporaryFile - it can hang)
                temp_dir = os.getenv('TEMP_DIR', '/tmp')
                har_path = os.path.join(temp_dir, f"har_{domain['id']}.har")

                context = None
                try:
                    # Create context with HAR recording enabled
                    context = await browser.new_context(record_har_path=har_path)
                    page = await context.new_page()

                    status, partial_params = await validate_domain(domain['name_text'], page)

                    logger.info(f"Validation complete for {domain['name_text']}, reading HAR...")

                    # Read HAR file if Outbrain is present
                    har_data = None
                    if status != 'not_using_outbrain' and os.path.exists(har_path):
                        try:
                            with open(har_path, 'r') as f:
                                har_content = f.read()

                            har_size_mb = len(har_content.encode('utf-8')) / (1024 * 1024)

                            if har_size_mb > 10:
                                logger.error(f"HAR file too large ({har_size_mb:.2f}MB) for {domain['name_text']}, skipping storage")
                            else:
                                har_data = har_content
                                logger.info(f"HAR file captured ({har_size_mb:.2f}MB) for {domain['name_text']}")
                        except Exception as ex:
                            logger.error(f"Failed to read HAR file for {domain['name_text']}: {str(ex)}")

                    logger.info(f"Updating database for {domain['name_text']}...")
                    update_domain_status(domain['id'], status, partial_params, har_data)
                    logger.info(f"Database updated for {domain['name_text']}")

                except Exception as ex:
                    logger.error(f"Critical error processing {domain['name_text']}: {str(ex)}")
                    update_domain_status(domain['id'], 'not_using_outbrain', None, None)
                finally:
                    logger.info(f"Cleaning up {domain['name_text']}...")
                    # Force close context with timeout protection
                    if context:
                        try:
                            logger.info(f"Closing context for {domain['name_text']}...")
                            await asyncio.wait_for(context.close(), timeout=5.0)
                            logger.info(f"Context closed for {domain['name_text']}")
                        except asyncio.TimeoutError:
                            logger.warning(f"Context close timeout for {domain['name_text']}")
                        except Exception as ex:
                            logger.warning(f"Error closing context for {domain['name_text']}: {str(ex)}")

                    # Clean up temporary HAR file
                    logger.info(f"Removing HAR file for {domain['name_text']}...")
                    if os.path.exists(har_path):
                        os.remove(har_path)
                    logger.info(f"Cleanup complete for {domain['name_text']}")

        # Force garbage collection after batch
        gc.collect()
        logger.info("Batch complete, browser cleaned up")


async def main():
    # Load environment variables from .env file
    load_dotenv()

    # Get batch limit from env (always require a number)
    batch_limit = int(os.getenv('DOMAIN_LIMIT', '1000'))

    # Fetch unprocessed domains
    logger.info("Fetching unprocessed domains...")
    domains = fetch_unprocessed_domains(limit=batch_limit)

    if not domains:
        logger.info("No unprocessed domains found!")
        return

    logger.info(f"Found {len(domains)} unprocessed domains")

    # Process in batches of 10
    await process_batch(domains, batch_size=10)

    logger.info("Validation complete!")
    sys.exit(0)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)

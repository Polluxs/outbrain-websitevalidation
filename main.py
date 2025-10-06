import asyncio
import gc
import gzip
import sys
import os
from enum import Enum
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
from camoufox.async_api import AsyncCamoufox
from dotenv import load_dotenv
from src.logging_config import logger


class OutbrainStatus(str, Enum):
    """Outbrain validation status"""
    NOT_USING = 'not_using_outbrain'
    ALL_PARAMS = 'using_outbrain_all_params'
    PARTIAL_PARAMS = 'using_outbrain_partial_params'

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
        return OutbrainStatus.NOT_USING, None

    # Look for Multivac API calls
    multivac_calls = [r for r in outbrain_requests if 'mv.outbrain.com/Multivac/api/get' in r]

    if not multivac_calls:
        # Outbrain is present but no Multivac call - still using Outbrain
        return OutbrainStatus.ALL_PARAMS, None

    # Parse parameters from first Multivac call
    parsed = urlparse(multivac_calls[0])
    params = parse_qs(parsed.query)
    found_params = set(params.keys())

    # Check if all expected params are present
    missing_params = EXPECTED_PARAMS - found_params
    extra_params = found_params - EXPECTED_PARAMS

    if not missing_params:
        # All expected parameters found
        return OutbrainStatus.ALL_PARAMS, None
    else:
        # Some parameters missing - this is weird
        result = {
            'found': sorted(list(found_params)),
            'missing': sorted(list(missing_params)),
            'extra': sorted(list(extra_params)) if extra_params else []
        }
        return OutbrainStatus.PARTIAL_PARAMS, str(result)


async def process_single_domain(browser, domain):
    """Process a single domain with context creation, validation, and cleanup"""
    domain_name = domain['name_text']
    domain_id = domain['id']
    temp_dir = os.getenv('TEMP_DIR', '/tmp')
    har_path = os.path.join(temp_dir, f"har_{domain_id}.har")

    context = None
    try:
        # Create context with HAR recording
        context = await browser.new_context(record_har_path=har_path)
        page = await context.new_page()

        # Validate if it uses outbrain
        status, partial_params = await validate_domain(domain_name, page)

        # Read HAR file if Outbrain is present
        har_data = None
        if status != OutbrainStatus.NOT_USING and os.path.exists(har_path):
            try:
                with open(har_path, 'r') as f:
                    har_content = f.read()

                har_size_mb = len(har_content.encode('utf-8')) / (1024 * 1024)

                if har_size_mb > 10:
                    logger.error("HAR file too large, skipping storage", extra={"domain": domain_name, "har_size_mb": round(har_size_mb, 2)})
                else:
                    har_data = har_content
                    logger.info("HAR file captured", extra={"domain": domain_name, "har_size_mb": round(har_size_mb, 2)})
            except Exception as ex:
                logger.error("Failed to read HAR file", extra={"domain": domain_name, "error": str(ex)})

        # Update database
        update_domain_status(domain_id, status, partial_params, har_data)
        logger.info("Completed domain processing", extra={"domain": domain_name, "status": status})

    finally:
        # Cleanup context
        if context:
            try:
                await asyncio.wait_for(context.close(), timeout=5.0)
            except Exception as ex:
                logger.warning("Failed to close context", extra={"domain": domain_name, "error": str(ex)})

        # Cleanup HAR file
        if os.path.exists(har_path):
            try:
                os.remove(har_path)
            except Exception as ex:
                logger.warning("Failed to remove HAR file", extra={"domain": domain_name, "error": str(ex)})


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

    try:
        # Listen to network requests
        page.on('request', handle_request)
        await page.goto(url, wait_until="load", timeout=30000)

        # Wait a bit for dynamic content to load
        await asyncio.sleep(2)

        return analyze_outbrain_requests(outbrain_requests)

    except Exception as e:
        logger.error("Domain validation failed", extra={"domain": domain_name, "url": url, "error": str(e)})
        return OutbrainStatus.NOT_USING, None


async def process_batch(domains, batch_size=10):
    """Process a batch of domains with browser recreation every 10"""
    total = len(domains)

    for i in range(0, total, batch_size):
        batch = domains[i:i + batch_size]
        batch_num = i // batch_size + 1
        batch_start = i + 1
        batch_end = min(i + batch_size, total)

        logger.info("Processing batch", extra={
            "batch_num": batch_num,
            "batch_start": batch_start,
            "batch_end": batch_end,
            "total_domains": total
        })

        # Clean up any leftover HAR files from previous crashes
        temp_dir = os.getenv('TEMP_DIR', '/tmp')
        try:
            har_files = [f for f in os.listdir(temp_dir) if f.endswith('.har')]
            if har_files:
                logger.info("Cleaning up leftover HAR files", extra={"har_file_count": len(har_files)})
                for har_file in har_files:
                    try:
                        os.remove(os.path.join(temp_dir, har_file))
                    except Exception as ex:
                        logger.warning("Could not remove HAR file", extra={"har_file": har_file, "error": str(ex)})
        except Exception as ex:
            logger.warning("Could not clean temp directory", extra={"error": str(ex)})

        # Create browser once per batch
        async with AsyncCamoufox(headless=True) as browser:
            for domain in batch:
                domain_name = domain['name_text']

                # Wrap entire domain processing in 60s timeout
                try:
                    await asyncio.wait_for(
                        process_single_domain(browser, domain),
                        timeout=60.0
                    )
                except asyncio.TimeoutError:
                    logger.error("Domain processing timeout, will retry later", extra={
                        "domain": domain_name,
                        "timeout_seconds": 60,
                        "batch_num": batch_num
                    })
                except Exception as ex:
                    logger.error("Domain processing failed, will retry later", extra={
                        "domain": domain_name,
                        "error": str(ex),
                        "batch_num": batch_num
                    })

        # Force garbage collection after batch
        gc.collect()
        logger.info("Batch complete", extra={"batch_num": batch_num})


async def main():
    # Load environment variables from .env file
    load_dotenv()

    # Get batch limit from env (always require a number)
    batch_limit = int(os.getenv('DOMAIN_LIMIT', '1000'))

    # Fetch unprocessed domains
    logger.info("Fetching unprocessed domains", extra={"limit": batch_limit})
    domains = fetch_unprocessed_domains(limit=batch_limit)

    if not domains:
        logger.info("No unprocessed domains found")
        return

    logger.info("Found unprocessed domains", extra={"domain_count": len(domains)})

    # Process in batches of 10
    await process_batch(domains, batch_size=10)

    logger.info("Validation complete", extra={"total_processed": len(domains)})
    sys.exit(0)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as ex:
        logger.error("Fatal error", extra={"error": str(ex)})
        sys.exit(1)

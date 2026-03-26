#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Simple in-domain image crawler with size filtering and optional delay."""

import argparse
import collections
import logging
import os
import random
import time
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from lxml import html
from PIL import Image

# Defaults
DEFAULT_URL = "https://wwwn.xxx.top"
DEFAULT_RULES = [
    'https://www.xxx.top',
    'https://xxx.top',
    'http://www.xxx.top',
    'http://xxx.top',
]
DEFAULT_OUTPUT_DIR = 'crawl_images'
DEFAULT_WIDTH = 30
DEFAULT_HEIGHT = 30


def normalize_url(raw_url):
    url, _ = urldefrag(raw_url)
    return url.strip()


def is_allowed_domain(link, allowed_prefixes):
    return any(link.startswith(prefix) for prefix in allowed_prefixes)


def download_image(image_url, output_dir, min_width, min_height, headers, timeout):
    try:
        r = requests.get(image_url, headers=headers, timeout=timeout)
        if r.status_code != 200:
            logging.debug('Skipping image %s status=%s', image_url, r.status_code)
            return None

        parsed = urlparse(image_url)
        filename = os.path.basename(parsed.path) or 'image'
        filename = filename.split('?')[0]
        filename = filename or 'image'

        os.makedirs(output_dir, exist_ok=True)

        now = time.localtime(time.time())
        name = '%04d-%02d-%02d-%02d-%02d-%02d-%s' % (
            now.tm_year,
            now.tm_mon,
            now.tm_mday,
            now.tm_hour,
            now.tm_min,
            now.tm_sec,
            filename,
        )
        file_path = os.path.join(output_dir, name)

        with open(file_path, 'wb') as f:
            f.write(r.content)

        try:
            img = Image.open(file_path)
            width, height = img.size
            img.close()

            if width <= min_width or height <= min_height:
                os.remove(file_path)
                logging.debug('Removed small image %s (%dx%d)', image_url, width, height)
                return None

            logging.info('Saved image %s (%dx%d) to %s', image_url, width, height, file_path)
            return file_path
        except Exception as ex:
            logging.warning('Failed to process image %s: %s', image_url, ex)
            try:
                os.remove(file_path)
            except OSError:
                pass
            return None

    except requests.RequestException as ex:
        logging.warning('Request failed for image %s: %s', image_url, ex)
        return None


def crawl(start_url, url_rules, output_dir, min_width, min_height, waf, max_pages, max_images):
    url_queue = collections.deque([start_url])
    url_crawled = set([start_url])
    url_image = set()

    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; ImageCrawler/1.0; +https://example.com/bot)'
    }

    pages = 0

    while url_queue:
        if max_pages > 0 and pages >= max_pages:
            logging.info('Reached max pages %d, stopping.', max_pages)
            break

        url = url_queue.popleft()
        logging.info('Crawling %s (queue len=%d)', url, len(url_queue))

        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code != 200:
                logging.warning('URL %s returned status %s', url, response.status_code)
                continue

            pages += 1

            content_body = html.fromstring(response.content)
            image_srcs = content_body.xpath('//img/@src')
            image_urls = {normalize_url(urljoin(response.url, src)) for src in image_srcs if src}

            logging.debug('Found %d images on %s', len(image_urls), url)

            for image in sorted(image_urls - url_image):
                saved = download_image(image, output_dir, min_width, min_height, headers, timeout=10)
                if saved:
                    url_image.add(image)

                if waf:
                    time.sleep(random.uniform(1.0, 2.0))

                if max_images > 0 and len(url_image) >= max_images:
                    logging.info('Reached max images %d, stopping.', max_images)
                    break

            if max_images > 0 and len(url_image) >= max_images:
                break

            link_hrefs = content_body.xpath('//a/@href')
            links = {
                normalize_url(urljoin(response.url, href))
                for href in link_hrefs
                if href and urljoin(response.url, href).startswith(('http://', 'https://'))
            }

            for link in sorted(links - url_crawled):
                if is_allowed_domain(link, url_rules):
                    url_crawled.add(link)
                    url_queue.append(link)

            if waf:
                time.sleep(random.uniform(1.0, 2.0))

        except requests.RequestException as ex:
            logging.warning('Failed to GET %s: %s', url, ex)
        except Exception:
            logging.exception('Unexpected error while crawling %s', url)

    logging.info('Crawl finished. pages=%d images=%d', pages, len(url_image))


def main():
    parser = argparse.ArgumentParser(description='Simple image crawler')
    parser.add_argument('--url', default=DEFAULT_URL, help='Start URL')
    parser.add_argument('--rules', nargs='+', default=DEFAULT_RULES, help='Allowed URL prefixes')
    parser.add_argument('--output-dir', default=DEFAULT_OUTPUT_DIR, help='Directory for downloaded images')
    parser.add_argument('--min-width', type=int, default=DEFAULT_WIDTH, help='Minimum image width')
    parser.add_argument('--min-height', type=int, default=DEFAULT_HEIGHT, help='Minimum image height')
    parser.add_argument('--waf', action='store_true', help='Enable delay between requests')
    parser.add_argument('--max-pages', type=int, default=0, help='Maximum number of pages to crawl (0=unlimited)')
    parser.add_argument('--max-images', type=int, default=0, help='Maximum number of images to download (0=unlimited)')
    parser.add_argument('--verbose', action='store_true', help='Verbose logging')

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
    )

    crawl(
        start_url=normalize_url(args.url),
        url_rules=[normalize_url(u) for u in args.rules],
        output_dir=args.output_dir,
        min_width=args.min_width,
        min_height=args.min_height,
        waf=args.waf,
        max_pages=args.max_pages,
        max_images=args.max_images,
    )


if __name__ == '__main__':
    main()

"""
Create a timeline of pledge promise value changes by scraping the OpenBSD manpage.

WARNING: this script is somewhat unreliable due to some promise values being 
    documented outside the main table.
"""

import time

import httpx
from bs4 import BeautifulSoup


def extract_promises(bs: BeautifulSoup):
    items = bs.select_one("#stdio").parent.select("dt")
    for i in items:
        yield i.text.strip()


def promises_for_version(version: str) -> set[str]:
    url = f"https://man.openbsd.org/OpenBSD-{version}/pledge"
    r = httpx.get(url)
    r.raise_for_status()

    bs = BeautifulSoup(r.text, "html.parser")
    return set(extract_promises(bs))


def main():
    lower_version = "5.9"
    upper_version = "7.8"

    promises = set()
    loop_lower = int(lower_version.replace(".", ""))
    loop_upper = int(upper_version.replace(".", "")) + 1
    for i in range(loop_lower, loop_upper):
        v = str(i)
        v = v[0] + "." + v[1]

        new_promises = promises_for_version(v)
        if promises != new_promises:
            added = new_promises - promises
            removed = promises - new_promises

            print(f"OpenBSD {v}:")
            if added:
                print(f"      Added: {added}")
            if removed:
                print(f"    Removed: {removed}")

            promises = new_promises

        time.sleep(3)  # avoid ratelimiting


if __name__ == "__main__":
    main()

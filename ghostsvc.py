#!/usr/bin/env python
"""Reconcile portal items against federated server services, and name the anonymously accessible services that appear in no sharing report.

A sharing report walks portal items. A service published straight to the
federated ArcGIS Server has no portal item, so it is on no sharing report, and
neither is a service whose item somebody deleted while the service kept
running. Both still answer to anyone who knows the url. The audit comes back
clean because the thing it audits is the item list, and these are not on it.

ArcGIS Server Manager already lists every service on the server, and the ArcGIS
API for Python reads the same list in two lines with server.services.list().
Both are right about the server. Neither one joins that list to the portal's
items, and the join is the job: the two sides describe the same service with
six different urls. Manager will also show you a service's permissions, which
is a configuration field rather than an observation. This tool asks the service
itself, with no token, and records what came back.

The engineering here is url normalisation, not the set difference. Two urls for
one service differ by scheme, by short host against fully qualified host, by
the web adaptor name, by a trailing slash, by case in the folder or service
name, by an explicit :6443 or :443, and by /rest/services against
/admin/services. Every one of those has to reconcile to a single key. Get it
wrong and the ghost list is entirely false positives, which is worse than no
list at all.

It is read-only. No flag changes anything on the server or in the portal, and
the only thing it writes is a report file, which needs --apply. (--self-test
also makes a temporary directory and removes it again.)

    python ghostsvc.py --self-test
    python ghostsvc.py --server https://gis.example.com/arcgis \\
        --portal https://portal.example.com/portal --token TOKEN
    python ghostsvc.py --server https://gis.example.com/arcgis \\
        --portal https://portal.example.com/portal --username gis_admin \\
        --out ghosts.csv --format csv --apply

Exit codes: 0 every service has an item and none answered anonymously (or
--no-probe was given and no ghost or orphan was found), 1 there are findings to
review, 2 the server or the portal could not be read, the report could not be
written, or a service could not be probed and nothing else was found, 64 usage
error.
"""

from __future__ import print_function

import argparse
import csv
import datetime
import getpass
import io
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# =============================================================================
# CONFIGURATION. Deliberately not constants at the call site.
# =============================================================================

# Ports that mean "the ArcGIS default" and therefore carry no information about
# which server a url points at. 443 and 80 are the web adaptor, 6443 and 6080
# are ArcGIS Server speaking for itself. The same service answers on the
# adaptor and on the server port, so a key that kept the port would report
# every service on the box as a ghost. Any OTHER port is kept, because a second
# site on 8443 really is a different service and merging it would hide a ghost.
DEFAULT_PORTS = (80, 443, 6080, 6443)

# The service types a url may end in, in the spelling ArcGIS uses. The last
# path segment has to be one of these or the url is refused rather than keyed,
# because a url this tool cannot read becomes a false ghost or a false orphan.
# The list is this tool's own, not copied from an Esri page. A type missing from
# it makes an item of that type unreadable and a catalog entry of that type
# abort the run, so add the spelling the server prints.
SERVICE_TYPES = (
    "MapServer", "FeatureServer", "ImageServer", "GPServer", "GeocodeServer",
    "GeometryServer", "GeoDataServer", "GlobeServer", "SceneServer",
    "StreamServer", "VectorTileServer", "NAServer", "MobileServer",
    "KnowledgeGraphServer", "VideoServer", "RelationalCatalogServer",
    "ParcelFabricServer", "UtilityNetworkServer", "VersionManagementServer",
    "ValidationServer", "TraceNetworkServer", "KMLServer", "WFSServer",
    "WMSServer", "WCSServer", "WMTSServer", "OGCFeatureServer", "SearchServer",
    "SchematicsServer", "WorkflowManagerServer",
)

# The server caps num on /sharing/rest/search whatever is asked for, and counts
# accurately only to SEARCH_CEILING. Both numbers are Esri's, not this tool's.
SEARCH_MAX_NUM = 100
SEARCH_CEILING = 10000

# Narrowest created-date range the item bisect will produce, and the epoch the
# root partition starts at. Created dates are epoch milliseconds.
DAY_MS = 86400000
EPOCH_START_MS = 0

# Item types the second bisect level splits on, used when one day still sits on
# the search ceiling. The list does not have to be complete: every split is a
# complement pair, so the half that is "none of these types" catches whatever
# is missing here.
BISECT_TYPES = (
    "Feature Service", "Map Service", "Image Service", "Vector Tile Service",
    "Scene Service", "Web Map", "Web Scene", "Web Mapping Application",
    "Dashboard", "StoryMap", "Form", "Notebook", "Geoprocessing Service",
    "Shapefile", "CSV", "File Geodatabase", "Service Definition", "PDF",
)

# Ceilings on how much of a portal or a server one run may visit. A portal that
# reports the search ceiling however narrow the query, or a server whose folder
# listing points back at itself, would otherwise run until the process died.
MAX_PARTITIONS = 4096
MAX_FOLDERS = 512

# Seconds before a call is abandoned. The probe gets its own, shorter, budget:
# a service that is down is the ordinary case for a probe and there may be
# hundreds of them, so waiting a minute each is an audit that never finishes.
HTTP_TIMEOUT = 60
PROBE_TIMEOUT = 20

# What replaces a secret anywhere it could otherwise be printed.
REDACTED = "[redacted]"

# Environment variable the password is read from. It is never a command line
# flag: argv is readable by every process on the box, and it lands in shell
# history, in scheduler logs and in this tool's own error messages.
SECRET_ENV = "GHOSTSVC_PASSWORD"

# Environment variable an existing portal token is read from when --token is
# not given. A token on the command line is exactly as visible as a password.
TOKEN_ENV = "GHOSTSVC_TOKEN"

# =============================================================================
# End of CONFIGURATION.
# =============================================================================

# How bad each finding is, worst first. A service that answers anonymously AND
# has no portal item is the one this tool exists for: nothing in the org points
# at it, so no sharing report will ever mention it, and anybody can read it.
SEVERITY = {
    "anonymous-ghost": 100,
    "anonymous": 80,
    "ghost": 50,
    "orphan": 20,
}

# Fields whose presence in a JSON answer marks it as a service description.
SERVICE_MARKERS = ("currentVersion", "serviceDescription", "capabilities",
                   "layers", "serviceDataType")

# Error codes in a 200 answer that mean "a token is needed": a definite no.
REFUSAL_CODES = (401, 403, 498, 499)

# Columns of the CSV report, in order. Fixed, because a spreadsheet somebody
# built a pivot table on top of must not gain a column between runs.
CSV_FIELDS = ("kind", "severity", "key", "service_url", "folder", "name",
              "type", "anonymous", "detail", "item_id", "item_title",
              "item_owner", "item_type", "item_access")

_TYPE_BY_LOWER = dict((t.lower(), t) for t in SERVICE_TYPES)

_HOST_NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")


class EnumerationIncomplete(RuntimeError):
    """The portal or the server could not be listed, so no reconcile is given.

    Raised rather than reporting what was read. A reconcile is a set
    difference, and half of one side missing does not make the answer half
    right: every item that was not enumerated turns into a ghost. A partial
    enumeration produces a confident list of services to go and investigate,
    all of which are fine.
    """


# ----------------------------------------------------------- url normalisation

def sanitize_url(url):
    """Drop the query string, the fragment and any user:password@ from a url.

    Called on every url before it is stored or printed. A portal item's url
    field and a service url both come back carrying whatever query string the
    publisher left on them, and on a federated deployment that is regularly a
    token. A url typed as https://user:password@host/... carries the credential
    in the authority instead. The report is a file that sits on a share for
    months.
    """
    raw = "%s" % (url or "")
    scheme, sep, rest = raw.partition("://")
    if not scheme.isalnum():
        # No scheme: a "://" inside a query string is not one.
        scheme, sep, rest = "", "", raw
    # A password may hold a / ? or # that RFC 3986 would read as the end of the
    # authority. The credential is cut at the last @ before anything else is
    # split, so none of it is left behind. An @ that follows a ? or # and has
    # a key=value or & between them is a query parameter such as e=a@b.com, not
    # a credential: cutting there would print the rest of the query, token
    # included. shortcut: a password that holds ?x=y before its @ is read as a
    # query and keeps its first part, which no real password does.
    at = rest.rfind("@")
    marks = [i for i in (rest.find("?"), rest.find("#")) if i >= 0]
    in_query = bool(marks) and min(marks) < at and any(
        c in rest[min(marks):at] for c in "=&")
    if at >= 0 and ":" in rest[:at] and not in_query:
        rest = rest[at + 1:]
    rest = rest.split("#", 1)[0]
    rest = rest.split("?", 1)[0]
    authority, slash, path = rest.partition("/")
    return scheme + sep + authority.rpartition("@")[2] + slash + path


def _short_host(host):
    """The name a host is known by, with its domain dropped.

    gis and gis.county.example.org are one machine, and a portal item created
    from inside the network usually carries the short form while the server
    catalog reports the fully qualified one. Taking the first label reconciles
    them.

    An address literal is returned whole. 10.0.0.5 and 10.0.0.6 are two servers
    and their first label is "10" for both, so shortening them would merge two
    machines into one key and hide every ghost on the second.
    """
    if not host:
        return ""
    if ":" in host:
        # An IPv6 literal. urlsplit strips the brackets off .hostname, so the
        # colons are the only thing left to recognise it by, and splitting it
        # on dots would return the whole address anyway.
        return host
    labels = host.split(".")
    if len(labels) > 1 and all(label.isdigit() for label in labels):
        return host                       # an IPv4 literal
    return labels[0]


def _split_path(path):
    """Path segments with the empty ones dropped.

    A doubled slash from a url somebody assembled by concatenation, and the
    trailing slash the browser adds, both produce empty segments. Dropping them
    is what makes .../rest/services/Roads/MapServer/ and
    .../rest//services/Roads/MapServer the same service.
    """
    return [seg for seg in path.split("/") if seg]


def _service_tail(segments, raw):
    """The folder-and-service part of a path, after the catalog marker.

    The marker is rest/services or admin/services. Everything before it is the
    web adaptor name, which is a deployment choice: /arcgis on one install,
    /server on the next, and nothing at all when the url goes straight to the
    server port. Everything after it identifies the service.

    The LAST marker wins. A reverse proxy that mounts the adaptor under a path
    of its own can produce two, and the one nearest the service is the real
    catalog root.
    """
    found = -1
    for index in range(1, len(segments)):
        if (segments[index].lower() == "services"
                and segments[index - 1].lower() in ("rest", "admin")):
            found = index
    if found < 0:
        raise ValueError(
            "%r has no /rest/services or /admin/services in it, so it does not "
            "name a service on an ArcGIS Server" % (raw,))
    return segments[found + 1:]


def service_key(url):
    """One key for every url that names the same service. Raises otherwise.

    This is the whole tool. The reconcile underneath it is a set difference,
    and a set difference is only as good as the key, so everything that can
    differ between the portal's idea of a url and the server's own is folded
    out here: the scheme, the domain, a default port, the web adaptor name, the
    trailing slash, the rest/admin split, and case in the folder and service
    name.

    Folder and service names are compared case-insensitively. Not folding case
    reports Roads/MapServer as a ghost because the item says roads/MapServer.
    Esri's documentation does not say whether a server may hold two services
    in one folder whose names differ only by case, so this is a decision and
    not a documented fact: a server that did hold both would see them keyed as
    one.

    Refusing a url is deliberate. A url this function cannot read has to be
    counted and reported as unreadable, because a key built from a guess is a
    ghost that does not exist, or an item that never matches the service it
    actually points at.
    """
    raw = ("%s" % (url or "")).strip()
    if not raw:
        raise ValueError("an empty url names no service")
    # A url with no scheme is common in portal item records typed by hand.
    # urlsplit puts the whole thing in the path unless it has an authority, so
    # the authority is given to it. A url that begins with a slash is a path on
    # some unnamed host and is refused below rather than guessed at.
    parts = urllib.parse.urlsplit(raw if "://" in raw else "//" + raw)
    host = (parts.hostname or "").lower()
    if not host:
        raise ValueError("%r names no host, so it cannot be matched against a "
                         "server catalog" % (raw,))
    try:
        port = parts.port
    except ValueError:
        # urlsplit defers this until .port is read. Left to raise on its own it
        # arrives as a bare "Port could not be cast to integer" with no url.
        raise ValueError("%r has a port that is not a number" % (raw,))
    key_host = _short_host(host)
    if port is not None and port not in DEFAULT_PORTS:
        key_host = "%s:%d" % (key_host, port)

    tail = _service_tail(_split_path(parts.path), raw)
    # The admin catalog spells a service Name.Type where the REST catalog
    # spells it Name/Type. Splitting the dot form here is what lets an admin
    # url and a rest url for one service meet.
    if tail and "." in tail[-1]:
        stem, _dot, suffix = tail[-1].rpartition(".")
        if stem and suffix.lower() in _TYPE_BY_LOWER:
            tail = tail[:-1] + [stem, suffix]
    # A trailing layer index. A portal item for one layer of a map service
    # points at .../MapServer/3, and it is that map service the server catalog
    # lists, so the index is dropped rather than making a service of its own.
    while tail and tail[-1].isdigit():
        tail = tail[:-1]
    if len(tail) < 2:
        raise ValueError("%r names no service under its catalog root" % (raw,))
    stype = _TYPE_BY_LOWER.get(tail[-1].lower())
    if not stype:
        raise ValueError("%r does not end in an ArcGIS service type, it ends "
                         "in %r" % (raw, tail[-1]))
    # Unquoted, because service_url percent-encodes the names it takes from the
    # catalog and an item url may carry the same name spelled either way.
    body = "/".join(urllib.parse.unquote(seg).lower() for seg in tail[:-1])
    return "%s/%s/%s" % (key_host, body, stype)


def keyed(url):
    """The key for a url, or None when the url cannot be read as a service."""
    try:
        return service_key(url)
    except ValueError:
        return None


def host_domain(url):
    """The domain part of a url's host, or "" when it has none to compare.

    service_key keeps only the first label of a host, so gis.alpha.example.org
    and gis.beta.example.net both key to "gis". The domain is what tells them
    apart again. A short name, an address literal and an empty host have no
    domain, and a url with none is compatible with any domain: nothing says it
    is a different machine.
    """
    raw = ("%s" % (url or "")).strip()
    parts = urllib.parse.urlsplit(raw if "://" in raw else "//" + raw)
    host = (parts.hostname or "").lower().rstrip(".")
    short = _short_host(host)
    return host[len(short) + 1:] if short != host else ""


def parse_host_aliases(values):
    """--host-alias ITEMHOST=SERVERHOST pairs as a dict, or raises ValueError.

    A portal item registered under a public name, maps.example.org, for a server
    the catalog calls gis-02.example.org, keys to a different host and reads as
    an orphan beside a ghost. The operator knows both names, and the tool
    cannot. Both sides are bare host names: a port is kept from the item url, and
    a url, a path or a credential is refused, so nothing typed here is ever
    requested.
    """
    aliases = {}
    for value in values or ():
        item_host, _eq, server_host = ("%s" % (value,)).partition("=")
        item_host, server_host = item_host.strip().lower(), server_host.strip()
        if not (_HOST_NAME.match(item_host) and _HOST_NAME.match(server_host)):
            raise ValueError("--host-alias must look like ITEMHOST=SERVERHOST, "
                             "two bare host names, got %r" % sanitize_url(value))
        aliases[item_host] = server_host.lower()
    return aliases


def alias_url(url, aliases):
    """The url with its host replaced when --host-alias names that host.

    Used for matching only. The item keeps the url it has in the report. A url
    the key could not read anyway is returned as it was.
    """
    raw = ("%s" % (url or "")).strip()
    if not aliases or not raw:
        return url
    try:
        parts = urllib.parse.urlsplit(raw if "://" in raw else "//" + raw)
        port = parts.port
    except ValueError:
        return url
    target = aliases.get((parts.hostname or "").lower().rstrip("."))
    if not target:
        return url
    return "%s://%s%s%s" % (parts.scheme or "https", target,
                            "" if port is None else ":%d" % port, parts.path)


def same_machine(left, right):
    """False only when both urls name a domain and the domains differ."""
    one, other = host_domain(left), host_domain(right)
    return not (one and other and one != other)


# ------------------------------------------------------------- server catalog

def service_record(raw, folder, root=""):
    """One service from a catalog listing, in the shape the reconcile wants.

    The two catalogs disagree about the field names and about the folder. REST
    reports a service inside a folder as "Transport/Roads" in its name and says
    nothing else; admin reports serviceName and folderName separately. Both are
    reduced here so that nothing downstream has to know which catalog was read.
    """
    if not isinstance(raw, dict):
        raise ValueError("a catalog entry is %r, not a service" % (raw,))
    name = "%s" % (raw.get("serviceName") or raw.get("name") or "")
    stype = "%s" % (raw.get("type") or "")
    if not name:
        raise ValueError("a catalog entry has no service name: %r" % (raw,))
    if not stype:
        raise ValueError("service %r has no type in the catalog" % (name,))
    in_name, _slash, bare = name.rpartition("/")
    folder = "%s" % (raw.get("folderName") or folder or in_name or "")
    folder = folder.strip("/")
    record = {"folder": folder, "name": bare, "type": stype}
    record["url"] = service_url(root, record) if root else ""
    record["key"] = service_key(record["url"]) if root else ""
    return record


def service_url(root, record):
    """The REST url of a service, which is the url a browser would open.

    Always the REST url, even when the catalog was read from admin. The finding
    exists so that somebody can paste the url and see what a stranger sees, and
    nobody without an admin token can open an admin url.

    Folder and service names come from the catalog and are percent-encoded, so
    a name holding @, ? or # cannot reach the probe as part of the authority
    or the query and send the request to another host.
    """
    base = sanitize_url(root).rstrip("/")
    parts = [base, "rest", "services"]
    if record.get("folder"):
        parts.append(_quoted_path(record["folder"].strip("/")))
    parts.append(_quoted_path(record["name"]))
    parts.append(_quoted_path(record["type"]))
    return "/".join(parts)


def _quoted_path(path):
    """Each segment of a catalog-supplied path, percent-encoded."""
    return "/".join(urllib.parse.quote(seg, safe="") for seg in path.split("/"))


def server_root(url):
    """The deployment root of a server url, whatever depth was passed in.

    --server is given as https://gis.example.com/arcgis, but the url an
    operator has to hand is usually the catalog they were just looking at. Both
    end up at the same root rather than at /arcgis/rest/services/rest/services.
    """
    trimmed = sanitize_url(url).rstrip("/")
    lowered = trimmed.lower()
    for suffix in ("/rest/services", "/admin/services", "/rest", "/admin"):
        if lowered.endswith(suffix):
            return trimmed[:-len(suffix)].rstrip("/")
    return trimmed


def walk_catalog(fetch, root="", max_folders=MAX_FOLDERS):
    """Every service on the server, walking every folder. Returns a list.

    fetch takes a folder name, "" for the root, and returns one parsed catalog
    response. Everything that needs a network lives behind it, which is why the
    walk can be driven by canned folders and no socket at all.

    Folders are visited once each. A catalog that lists itself among its own
    folders, which a proxy rewriting paths can produce, would otherwise be
    walked until the process died.
    """
    if max_folders < 1:
        raise ValueError("--max-folders must be at least 1")
    pending = [""]
    seen = set()
    services = []
    visited = 0
    while pending:
        folder = pending.pop(0)
        if folder.lower() in seen:
            continue
        seen.add(folder.lower())
        visited += 1
        if visited > max_folders:
            raise EnumerationIncomplete(
                "gave up after %d folder(s), still at %r. A catalog this deep "
                "is a folder listing that points back at itself."
                % (max_folders, folder))
        body = fetch(folder)
        if not isinstance(body, dict):
            raise ValueError("the catalog for folder %r answered with a %s, "
                             "not a service listing"
                             % (folder, type(body).__name__))
        if "services" not in body and "folders" not in body:
            # An admin call that failed says so inside a 200 and has neither,
            # and read as an empty catalog it turns every item into an orphan.
            raise ValueError("the catalog for folder %r has no services and no "
                             "folders member, so it is not a service listing"
                             % (folder,))
        for sub in body.get("folders") or []:
            sub = ("%s" % (sub,)).strip().strip("/")
            if sub:
                pending.append(sub)
        for raw in body.get("services") or []:
            services.append(service_record(raw, folder, root))
    return services


# ------------------------------------------------------- the anonymity verdict

def is_anonymous(status, body, error=None):
    """Did this response prove the service answers with no token at all?

    Returns (verdict, reason). The verdict is the audit deliverable, so it is
    made from what came back rather than from a permissions field: a service
    can be configured private and still answer, because the permission lives on
    the server while the web adaptor in front of it was installed without web
    tier authentication.

    A positive signal is required. An ArcGIS deployment behind IWA or SAML
    answers an unauthenticated request with HTTP 200 and the login page, so
    "the request did not fail" is not evidence of anything. The response has to
    look like a service description.
    """
    if error:
        return False, "%s" % (error,)
    status = int(status)
    if status != 200:
        return False, "HTTP %d" % status
    if not isinstance(body, dict):
        return False, ("the response was not a service description, which is "
                       "what a login page looks like from here")
    err = body.get("error")
    if isinstance(err, dict):
        return False, "%s %s" % (err.get("code"), err.get("message"))
    for marker in SERVICE_MARKERS:
        if marker in body:
            return True, "answered with %s and no token" % marker
    return False, "the response carried no service description"


def probe_conclusive(status, body, error=None):
    """Did the probe get a definite yes or a definite no out of the service?

    is_anonymous says False for a service that refused and also for a service
    that was down, and those are not the same finding. A refusal (401, 403, a
    login page, an error envelope that asks for a token) is a no. A service
    that never answered, an HTTP 500 or 404 and an error nobody recognises
    leave the question open, and an audit that counts them as no reports a
    clean result it did not earn.
    """
    if error:
        return False
    status = int(status)
    if status in (401, 403):
        return True
    if status != 200:
        return False
    if not isinstance(body, dict):
        return True                        # a login page: the deployment said no
    err = body.get("error")
    if isinstance(err, dict):
        return err.get("code") in REFUSAL_CODES
    return any(marker in body for marker in SERVICE_MARKERS)


# --------------------------------------------------------- portal enumeration

def clamp_num(num):
    """Clamp a page size to what the portal will actually honour.

    Clamped before the request rather than after the response, so that the
    paging loop and the server agree about the page size from the first call.
    """
    if not isinstance(num, int) or isinstance(num, bool):
        raise ValueError("page size must be an integer, got %r" % (num,))
    if num < 1:
        raise ValueError("page size must be at least 1, got %r" % (num,))
    return min(num, SEARCH_MAX_NUM)


def is_capped(total):
    """True when a reported total has reached the ceiling and means nothing.

    The comparison is >=, not >. Exactly 10,000 is the cap value itself: an org
    with 10,000 items and one with 400,000 both report 10,000 here.
    """
    return int(total) >= SEARCH_CEILING


def next_start(page, start, returned):
    """Where the next page begins, or None when this query is finished.

    The server's own nextStart is authoritative and -1 is its end marker. When
    the response omits it, the next page begins after the rows that ACTUALLY
    came back, never after the page size that was asked for: the server clamps
    num without saying so.
    """
    if start < 1:
        raise ValueError("start is 1-based, got %r" % (start,))
    if returned < 0:
        raise ValueError("a page cannot return %r rows" % (returned,))
    if returned == 0:
        return None
    nxt = page.get("nextStart")
    if nxt is None:
        nxt = start + returned
    nxt = int(nxt)
    if nxt <= 0:
        return None
    if nxt <= start:
        raise ValueError("nextStart %d does not advance past start %d, which "
                         "would page the same rows for ever" % (nxt, start))
    if nxt > SEARCH_CEILING:
        return None
    return nxt


def quote_term(term):
    """Quote one query term, and refuse a term that would break the query.

    A term carrying its own double quote closes the string early and silently
    changes which items the query selects, which here means a slice of the org
    that nothing enumerates and a page of ghosts that all have items.
    """
    term = "%s" % (term,)
    if not term.strip():
        raise ValueError("a query term cannot be empty")
    if '"' in term:
        raise ValueError("query term %r contains a double quote" % (term,))
    if " " in term or ":" in term or "(" in term or ")" in term:
        return '"%s"' % term
    return term


def type_clause(terms, negated=False):
    """A 'type:(a OR b)' clause, or its complement with a leading minus.

    The complement is what makes the bisect safe. Splitting types into "these"
    and "those" is exhaustive only when the type list is complete, and Esri
    adds item types every release. Splitting into "these" and "not these" is
    exhaustive by construction.
    """
    terms = tuple(terms)
    if not terms:
        raise ValueError("a type clause needs at least one term")
    body = " OR ".join(quote_term(t) for t in terms)
    return "%stype:(%s)" % ("-" if negated else "", body)


class Partition(object):
    """One slice of the organization: a created-date range and its clauses."""

    def __init__(self, base, lo, hi, clauses=(), types=()):
        lo, hi = int(lo), int(hi)
        if lo > hi:
            raise ValueError("partition range is backwards: %d > %d" % (lo, hi))
        if lo < 0:
            raise ValueError("a created date cannot be negative: %d" % lo)
        self.base = base or ""
        self.lo = lo
        self.hi = hi
        self.clauses = tuple(clauses)
        self.types = tuple(types)

    def divisible(self):
        """True when bisect() has something left to split this on."""
        return (self.hi - self.lo >= DAY_MS) or bool(self.types)

    def child(self, lo=None, hi=None, clause=None, types=None):
        """A copy with one more clause, or a narrower date range."""
        return Partition(self.base,
                         self.lo if lo is None else lo,
                         self.hi if hi is None else hi,
                         self.clauses + ((clause,) if clause else ()),
                         self.types if types is None else types)

    def __repr__(self):
        return "Partition(%r)" % (partition_query(self),)


def partition_query(part):
    """Render a partition as the q parameter search is given.

    The base query is parenthesised. An operator passing 'owner:jsmith OR
    owner:ann' would otherwise have the date range AND itself onto the last
    term only, and the enumeration would cover a different org than the one
    the server list is being reconciled against.
    """
    parts = []
    if part.base:
        parts.append("(%s)" % part.base)
    parts.append("created:[%d TO %d]" % (part.lo, part.hi))
    parts.extend(part.clauses)
    return " AND ".join(parts)


def bisect(part):
    """Split one partition into two whose union is exactly the parent.

    Created date first, then item type. Date is first because it always works
    and needs nothing read from the portal. Type is second because a day with
    more than 10,000 items is a bulk publish and a bulk publish is one type.
    """
    if part.hi - part.lo >= DAY_MS:
        mid = part.lo + (part.hi - part.lo) // 2
        return part.child(hi=mid), part.child(lo=mid + 1)
    if part.types:
        cut = max(1, len(part.types) // 2)
        head, tail = tuple(part.types[:cut]), tuple(part.types[cut:])
        # A single term cannot be halved again, so the matching child carries
        # no candidates forward and terminates instead of emitting
        # type:(a) AND type:(a) until the partition budget runs out.
        inside = head if len(head) > 1 else ()
        # The wider positive clause this one replaces is dropped. search is a
        # GET, and a query that gained a clause at every level reached the url
        # length limit and came back 414 before it divided the partition.
        kept = tuple(c for c in part.clauses if not c.startswith("type:("))
        hit = Partition(part.base, part.lo, part.hi,
                        kept + (type_clause(head),), types=inside)
        miss = part.child(clause=type_clause(head, True), types=tail)
        return hit, miss
    raise EnumerationIncomplete(
        "this query still reports the %d result ceiling and there is nothing "
        "left to split it on: %s. It covers one day and one item type, so the "
        "organization holds more than %d items identical on both. The items "
        "under it cannot be enumerated, and every one of them would be "
        "reported as a ghost service."
        % (SEARCH_CEILING, partition_query(part), SEARCH_CEILING))


def reconcile_pages(query, totals, collected):
    """Warnings about one partition's crawl. Empty when it reconciles.

    The totals are every value the server reported, one per page. A total that
    moves mid-crawl means items were created or deleted while the enumeration
    ran, and an item created mid-crawl that the enumeration missed is a ghost
    on the report tomorrow morning.
    """
    out = []
    if not totals:
        return out
    if len(set(totals)) > 1:
        out.append("the reported total moved from %d to %d while %s was being "
                   "read, so items were created or deleted mid-crawl"
                   % (totals[0], totals[-1], query))
    final = int(totals[-1])
    if not is_capped(final) and int(collected) != final:
        out.append("%s reported %d item(s) and returned %d"
                   % (query, final, collected))
    return out


def crawl_partition(fetch, query, num=SEARCH_MAX_NUM):
    """Page one query to its end. Returns (items by id, totals seen, pages)."""
    size = clamp_num(num)
    items = {}
    totals = []
    pages = 0
    start = 1
    while start is not None:
        page = fetch(query, start, size)
        if not isinstance(page, dict):
            raise ValueError("fetch returned %r, which is not a search response"
                             % (page,))
        pages += 1
        totals.append(int(page.get("total") or 0))
        results = page.get("results") or []
        for raw in results:
            if not isinstance(raw, dict):
                raise ValueError("a search result is a %s, not an object"
                                 % type(raw).__name__)
            iid = raw.get("id")
            if not iid:
                # The title and the sanitised url, never the raw result: its
                # url may carry the token its publisher registered it with.
                raise ValueError("a search result has no id (title %r, url %r)"
                                 % (raw.get("title"),
                                    sanitize_url(raw.get("url"))))
            # Union by id. Two partitions that overlap, because an item was
            # edited between them, contribute that item once.
            items[iid] = raw
        start = next_start(page, start, len(results))
    return items, totals, pages


def enumerate_items(fetch, base="", types=BISECT_TYPES, now_ms=None,
                    num=SEARCH_MAX_NUM, max_partitions=MAX_PARTITIONS,
                    echo=None):
    """Every item the base query matches. Returns (items by id, warnings).

    Depth first, not breadth first. A partition that will never come under the
    ceiling has to be found by descending into it, and the refusal is the
    useful answer: an enumeration that stopped at 10,000 would turn every item
    above the cap into a ghost service on the report.
    """
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    if max_partitions < 1:
        raise ValueError("--max-partitions must be at least 1")
    pending = [Partition(base, EPOCH_START_MS, int(now_ms), types=tuple(types))]
    items = {}
    warnings = []
    visited = 0
    while pending:
        part = pending.pop()
        visited += 1
        if visited > max_partitions:
            raise EnumerationIncomplete(
                "gave up after %d partitions, still at %s. Either the portal "
                "reports the ceiling for every query, or the organization "
                "needs a narrower --query."
                % (max_partitions, partition_query(part)))
        query = partition_query(part)
        got, totals, _pages = crawl_partition(fetch, query, num)
        total = totals[-1] if totals else 0
        if is_capped(total):
            # The rows just read are thrown away on purpose. They are at most
            # the first 10,000 of an unknown number, and the two children
            # cover this partition exactly, so nothing is lost.
            left, right = bisect(part)
            if echo:
                echo("  at the %d ceiling, splitting: %s"
                     % (SEARCH_CEILING, query))
            pending.append(right)
            pending.append(left)
            continue
        warnings.extend(reconcile_pages(query, totals, len(got)))
        items.update(got)
        if echo:
            echo("  %d item(s) from %s" % (len(got), query))
    return items, warnings


# ------------------------------------------------------------- the reconcile

def item_record(raw):
    """Keep the report fields of a search result and drop the rest.

    The url is kept, because the url is the finding, but its query string is
    not: a portal item's url regularly carries the token the publisher had
    when they registered it.
    """
    return {
        "id": raw.get("id") or "",
        "title": raw.get("title") or "",
        "owner": raw.get("owner") or "",
        "type": raw.get("type") or "",
        "access": raw.get("access") or "private",
        "url": sanitize_url(raw.get("url") or ""),
    }


class Finding(object):
    """One service, or one item, that the reconcile wants somebody to look at."""

    def __init__(self, kind, key, service=None, items=(), detail="",
                 tested=True):
        if kind not in SEVERITY:
            raise ValueError("%r is not a finding kind" % (kind,))
        self.tested = tested
        self.kind = kind
        self.severity = SEVERITY[kind]
        self.key = key
        self.service = dict(service) if service else None
        self.items = [item_record(it) for it in items]
        self.detail = detail

    @property
    def url(self):
        """The service url, or the item's url for an orphan."""
        if self.service:
            return sanitize_url(self.service.get("url") or "")
        return self.items[0]["url"] if self.items else ""

    @property
    def anonymous(self):
        return self.kind in ("anonymous", "anonymous-ghost")

    def sort_key(self):
        return (-self.severity, self.key,
                self.items[0]["id"] if self.items else "")

    def __repr__(self):
        return "Finding(%r, %r)" % (self.kind, self.key)


class Report(object):
    """The finished reconcile: what was compared and what came out of it."""

    def __init__(self, findings, services, items, unreadable, warnings=(),
                 probes=None):
        # probes maps a service key to True when its probe was conclusive and
        # to False when it was not. None means every service was probed, and
        # an empty dict means the probe was skipped.
        self.probes = probes
        self.findings = sorted(findings, key=lambda f: f.sort_key())
        self.services = services
        self.items = items
        self.unreadable = list(unreadable)
        self.warnings = list(warnings)

    def of_kind(self, kind):
        return [f for f in self.findings if f.kind == kind]

    @property
    def ghosts(self):
        return self.of_kind("ghost") + self.of_kind("anonymous-ghost")

    @property
    def anonymous(self):
        return [f for f in self.findings if f.anonymous]

    @property
    def orphans(self):
        return self.of_kind("orphan")

    @property
    def untested(self):
        """Keys of the services nobody got an answer about."""
        if self.probes is None:
            return []
        return sorted(set(s["key"] for s in self.services
                          if not self.probes.get(s["key"])))

    @property
    def probe_skipped(self):
        return self.probes is not None and not self.probes

    @property
    def probe_failed(self):
        """The probe ran and not one service gave a definite answer."""
        return bool(self.probes) and not any(self.probes.values())

    @property
    def matched(self):
        """Services that have a portal item and did not answer anonymously."""
        flagged = set(f.key for f in self.findings if f.service)
        return len(set(s["key"] for s in self.services) - flagged)

    def __repr__(self):
        return "Report(%d finding(s), %d service(s), %d item(s))" % (
            len(self.findings), len(self.services), len(self.items))


def reconcile(services, items, anonymous=(), details=None, probes=None,
              aliases=None):
    """Join a server catalog to a portal item list and report the difference.

    A service and an item meet when their urls normalise to the same key, which
    is the only reason service_key is worth as much code as it is. Everything
    here is a set operation over those keys. aliases is the --host-alias map,
    applied to the item side only.
    """
    anon = set(anonymous)
    details = details or {}
    by_key = {}
    unreadable = []
    claimed = set()
    for raw in items:
        key = keyed(alias_url(raw.get("url"), aliases))
        if key is None:
            # An item with no url, or with a url that does not name a service,
            # cannot be an orphan: there is no service it claims to have. A web
            # map is the ordinary case. Counted and reported rather than
            # dropped, so that a portal full of urls this tool cannot read is
            # visible instead of looking like a clean org.
            unreadable.append(item_record(raw))
            continue
        by_key.setdefault(key, []).append(raw)

    findings = []
    for svc in services:
        key = svc["key"]
        # The key folds a host to its first label, so an item on a different
        # domain with the same first label is another server's service, not
        # this one's.
        mine = [raw for raw in by_key.get(key) or []
                if same_machine(alias_url(raw.get("url"), aliases),
                                svc.get("url"))]
        claimed.update(id(raw) for raw in mine)
        open_to_all = key in anon
        if open_to_all and not mine:
            kind = "anonymous-ghost"
        elif open_to_all:
            kind = "anonymous"
        elif not mine:
            kind = "ghost"
        else:
            continue
        tested = probes is None or bool(probes.get(key))
        findings.append(Finding(kind, key, svc, mine, details.get(key, ""),
                                tested))
    for key in sorted(by_key):
        for raw in by_key[key]:
            if id(raw) not in claimed:
                # An orphan names a service this server never listed, so
                # it is never probed and its anonymity is unknown.
                findings.append(Finding("orphan", key, None, [raw],
                                        tested=False))
    return Report(findings, list(services), list(items), unreadable,
                  probes=probes)


def build_report(server, portal, query, taken, report):
    """Assemble the report document. No credential ever enters it."""
    return {
        "ghostsvc": 1,
        "server": sanitize_url(server),
        "portal": sanitize_url(portal),
        "query": query,
        "taken": taken,
        "services": len(report.services),
        "items": len(report.items),
        "matched": report.matched,
        "ghosts": len(report.ghosts),
        "orphans": len(report.orphans),
        "anonymous": len(report.anonymous),
        "unprobed": len(report.untested),
        "warnings": list(report.warnings),
        "unreadable_items": sorted(report.unreadable, key=lambda r: r["id"]),
        "findings": [finding_record(f) for f in report.findings],
    }


def finding_record(finding):
    """One finding as the JSON document and the CSV row both see it."""
    svc = finding.service or {}
    return {
        "kind": finding.kind,
        "severity": finding.severity,
        "key": finding.key,
        "service_url": finding.url,
        "folder": svc.get("folder", ""),
        "name": svc.get("name", ""),
        "type": svc.get("type", ""),
        "anonymous": finding.anonymous if finding.tested else None,
        "detail": finding.detail,
        "items": list(finding.items),
    }


FORMULA_LEADS = ("=", "+", "-", "@", "\t", "\r")


def cell(value):
    """A text cell a spreadsheet will not run as a formula.

    A cell that starts with = + - @ tab or carriage return gets one leading
    apostrophe. Service names, folders and item titles are typed by whoever
    published them, so a title of =HYPERLINK(...) would otherwise run on the
    machine of the person who opens the report. Only text goes through here:
    severity stays a number.
    """
    text = "%s" % (value,)
    if text[:1] in FORMULA_LEADS:
        return "'" + text
    return text


def csv_rows(document):
    """The report flattened to one row per finding per item.

    A finding with three items becomes three rows. A spreadsheet is filtered
    and sorted by column, and one row holding three item ids cannot be.
    Every text cell passes through cell(). kind, severity and the yes/no
    column are written by this tool, never by the data, so they do not.
    """
    rows = []
    for rec in document["findings"]:
        base = [rec["kind"], rec["severity"], cell(rec["key"]),
                cell(rec["service_url"]), cell(rec["folder"]),
                cell(rec["name"]), cell(rec["type"]),
                {True: "yes", False: "no", None: ""}[rec["anonymous"]],
                cell(rec["detail"])]
        if not rec["items"]:
            rows.append(base + ["", "", "", "", ""])
            continue
        for item in rec["items"]:
            rows.append(base + [cell(item["id"]), cell(item["title"]),
                                cell(item["owner"]), cell(item["type"]),
                                cell(item["access"])])
    return rows


def describe(report):
    """Render a reconcile as the lines the CLI prints."""
    out = ["%d service(s) on the server, %d portal item(s) enumerated, "
           "%d service(s) with an item and no finding"
           % (len(report.services), len(report.items), report.matched)]
    if report.unreadable:
        out.append("%d portal item(s) carried no url this tool could read, so "
                   "they were not reconciled" % len(report.unreadable))
    if report.warnings:
        out.append("")
        out.append("ENUMERATION WARNINGS")
        for warning in report.warnings:
            out.append("  - %s" % warning)
        out.append("The portal changed while it was being read, so a service "
                   "below may have an item after all.")
    if report.probe_skipped:
        out.append("The anonymous probe was not run, so nothing is known "
                   "about who can read these services.")
    elif report.untested:
        out.append("%d of %d service(s) could not be probed, so they are "
                   "neither reported anonymous nor cleared. Run again when "
                   "they answer." % (len(report.untested), len(report.services)))
    out.append("")
    if not report.findings:
        if report.warnings:
            out.append("No finding, but the enumeration warned above, so this "
                       "is not a clean result. Run again.")
        elif report.probe_skipped:
            out.append("Every service on the server has a portal item.")
        elif report.probe_failed:
            out.append("Every service on the server has a portal item, but no "
                       "probe got an answer, so nothing is known about who "
                       "can read them.")
        elif report.untested:
            out.append("Every service on the server has a portal item, and "
                       "every service that could be probed refused without a "
                       "token.")
        else:
            out.append("Every service on the server has a portal item, and not "
                       "one of them answered")
            out.append("without a token.")
        return out
    out.append("%d finding(s): %d anonymous, %d ghost(s), %d orphan(s)"
               % (len(report.findings), len(report.anonymous),
                  len(report.ghosts), len(report.orphans)))
    out.append("")
    for finding in report.findings:
        out.append("[%3d] %-16s %s" % (finding.severity, finding.kind,
                                       finding.url))
        if finding.detail:
            out.append("        %s" % finding.detail)
        for item in finding.items:
            out.append("        - %s (%s, %s) %s"
                       % (item["title"], item["type"], item["access"],
                          item["id"]))
    return out


def exit_code(report):
    """0 when there is nothing to look at, 1 when there is, 2 when unsure.

    A probe that left even one service without a definite answer cannot give a
    clean result, because that service might be open to everyone. Findings
    still win: a ghost is worth reading whether or not the probe worked.
    A run that skipped the probe on request (--no-probe) answered the only
    question it was asked, so it is not unsure.

    An enumeration warning is the same kind of doubt. A portal that moved while
    it was read may hold an item this run never saw, so a run with no finding
    and a warning is not clean.
    """
    if report.findings:
        return 1
    unsure = report.warnings or (report.untested and not report.probe_skipped)
    return 2 if unsure else 0


# ------------------------------------------------------------------- plumbing

def is_http_url(url):
    """True when urllib will actually open this url.

    A url typed without its scheme is the common mistake, and urllib answers it
    by raising an exception that quotes the whole url back, query string and
    token included.
    """
    return bool(url) and url.lower().startswith(("http://", "https://"))


def redact(text, *secrets):
    """Remove secrets from anything about to be printed or written.

    urllib repeats the request in some error messages and generateToken is a
    POST, so an unredacted traceback is a password in a log file.
    """
    out = "%s" % (text,)
    for secret in secrets:
        if secret:
            # Coerced because this runs inside an exception handler, where a
            # secret that arrived as anything but a string used to raise
            # TypeError and throw away the redaction with it.
            plain = "%s" % (secret,)
            # The form-encoded and percent-encoded spellings too: a server
            # that echoes the POST body back quotes a password like p@ss as
            # p%40ss.
            for spelling in (plain, urllib.parse.quote_plus(plain),
                             urllib.parse.quote(plain, safe="")):
                out = out.replace(spelling, REDACTED)
    return out


def printable(text, encoding):
    """Make one line safe for a console that cannot encode it.

    ArcGIS Pro runs on Windows, where stdout is cp1252 unless somebody changed
    it, and one service whose title held a character that code page has no room
    for aborted the whole report with UnicodeEncodeError.
    """
    if not encoding:
        return text
    try:
        text.encode(encoding)
    except UnicodeEncodeError:
        return text.encode(encoding, "replace").decode(encoding, "replace")
    except LookupError:
        return text
    return text


def utcnow():
    """UTC now, without datetime.utcnow().

    utcnow() is deprecated from 3.12 and datetime.UTC does not exist before
    3.11, so timezone.utc is the spelling that works on ArcGIS Pro's Python and
    on a current python3 alike.
    """
    return datetime.datetime.now(datetime.timezone.utc)


# ------------------------------------------------------------------ server i/o

def _opener(insecure):
    """Build a urllib opener, optionally without certificate verification.

    Enterprise deployments behind an internal CA are the reason --insecure
    exists. It is off by default and refused together with a password, because
    posting credentials down an unverified connection is the failure it would
    cause.
    """
    if not insecure:
        return urllib.request.build_opener()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context))


def _get(endpoint, params, insecure=False, post=False, secret=None,
         timeout=HTTP_TIMEOUT):
    """One REST call returning parsed JSON, with the server's own errors raised.

    ArcGIS answers HTTP 200 with an error object in the body, so the status
    code proves nothing and the body has to be read every time.
    """
    params = dict(params)
    params["f"] = "json"
    data = urllib.parse.urlencode(params).encode("utf-8")
    opener = _opener(insecure)
    try:
        if post:
            response = opener.open(endpoint, data, timeout=timeout)
        else:
            response = opener.open("%s?%s" % (endpoint, data.decode("utf-8")),
                                   timeout=timeout)
        body = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        # Every credential this request carried, not only the caller's secret.
        # urllib quotes the full url back for a scheme-less --server, and that
        # url carries the token.
        raise RuntimeError(redact("%s: %s" % (endpoint, exc), secret,
                                  params.get("token"), params.get("password")))
    if not isinstance(body, dict):
        # A captive portal login page, a proxy error page and a load balancer's
        # maintenance notice can all parse as valid JSON without being an
        # ArcGIS response, and every caller below goes straight to body.get().
        raise RuntimeError("%s: answered with a JSON %s, not an object, so "
                           "this is not an ArcGIS response"
                           % (endpoint, type(body).__name__))
    problem = _error_text(body)
    if problem:
        raise RuntimeError(redact("%s: %s" % (endpoint, problem), secret,
                                  params.get("token"), params.get("password")))
    return body


def _error_text(body):
    """What a 200 answer says went wrong, or "" when it says nothing did.

    The portal and the services directory use {"error": {"code", "message"}}.
    The Administrator API uses {"status": "error", "messages": [...], "code"}.
    A proxy may put a bare string under "error". All three are failures.
    """
    err = body.get("error")
    if isinstance(err, dict):
        return "%s %s" % (err.get("code"), err.get("message"))
    if err:
        return "%s" % (err,)
    if body.get("status") == "error":
        return "%s %s" % (body.get("code"),
                          "; ".join("%s" % (m,)
                                    for m in body.get("messages") or []))
    return ""


def portal_call(url, path, params, insecure=False, post=False, secret=None):
    """One /sharing/rest call."""
    endpoint = "%s/sharing/rest/%s" % (sanitize_url(url).rstrip("/"),
                                       path.lstrip("/"))
    return _get(endpoint, params, insecure=insecure, post=post, secret=secret)


def catalog_fetch(root, token, admin=False, insecure=False):
    """Build the fetch callable walk_catalog drives."""
    base = "%s/%s/services" % (server_root(root), "admin" if admin else "rest")

    def fetch(folder):
        endpoint = "%s/%s" % (base, _quoted_path(folder)) if folder else base
        params = {"token": token} if token else {}
        return _get(endpoint, params, insecure=insecure, secret=token)
    return fetch


def probe_service(url, insecure=False, timeout=PROBE_TIMEOUT):
    """Ask a service for its description with NO token. Returns what came back.

    Returns (status, parsed body or None, transport error or None), which
    is_anonymous turns into the verdict. The split is what lets the verdict be
    asserted against every shape of response without a socket.

    No token is sent, ever. That is the entire experiment: a service that
    answers this request answers it for anybody on the network, whatever the
    permissions page says it should do.
    """
    target = "%s?f=json" % sanitize_url(url)
    opener = _opener(insecure)
    try:
        response = opener.open(target, timeout=timeout)
        status = getattr(response, "status", None) or 200
        raw = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        # A 401 or a 403 is the answer, not a failure. It is the deployment
        # saying no, which is what this probe is looking for.
        return int(exc.code), None, None
    except Exception as exc:
        return 0, None, redact("%s" % (exc,))
    try:
        body = json.loads(raw)
    except ValueError:
        # A login page. Not a failure either: it is the deployment saying no in
        # HTML rather than in JSON.
        body = None
    return int(status), body, None


def probe_all(services, insecure=False, timeout=PROBE_TIMEOUT, echo=None,
              probe=None, unanswered=None):
    """Probe every service. Returns (anonymous keys, reason per key).

    unanswered, when given, is a set that receives the key of every service
    whose probe was not conclusive, so the caller can tell "refused" from
    "could not be asked".
    """
    probe = probe or probe_service
    anon = set()
    details = {}
    for svc in services:
        status, body, error = probe(svc["url"], insecure, timeout)
        verdict, reason = is_anonymous(status, body, error)
        details[svc["key"]] = reason
        if unanswered is not None and not probe_conclusive(status, body, error):
            unanswered.add(svc["key"])
        if verdict:
            anon.add(svc["key"])
            if echo:
                echo("  ANONYMOUS %s" % svc["url"])
    return anon, details


def read_secret(username):
    """Get the password from the environment, or prompt for it.

    Never from argv. getpass keeps it off the screen, and it is passed on to
    redact() so that nothing downstream can print it back out.
    """
    secret = os.environ.get(SECRET_ENV)
    if secret:
        return secret
    try:
        return getpass.getpass("password for %s (not echoed): " % username)
    except EOFError:
        raise RuntimeError("no password for %s: %s is not set and there is "
                           "no terminal to ask on. Set %s in the environment "
                           "of the scheduled job." % (username, SECRET_ENV,
                                                      SECRET_ENV))


def generate_token(url, username, secret, insecure=False):
    """Exchange a username and password for a short-lived portal token."""
    body = portal_call(url, "generateToken", {
        "username": username,
        "password": secret,
        "client": "referer",
        "referer": sanitize_url(url),
        "expiration": 60,
    }, insecure=insecure, post=True, secret=secret)
    token = body.get("token")
    if not token:
        raise RuntimeError("generateToken returned no token")
    return token


def org_id(url, token, insecure=False):
    """The signed-in organization's id, or None when the portal will not say."""
    params = {"token": token} if token else {}
    body = portal_call(url, "portals/self", params, insecure=insecure,
                       secret=token)
    return body.get("id")


def portal_fetch(url, token, insecure=False):
    """Build the fetch callable the item enumeration drives."""
    def fetch(query, start, num):
        params = {"q": query, "start": start, "num": num,
                  "sortField": "created", "sortOrder": "asc"}
        if token:
            params["token"] = token
        return portal_call(url, "search", params, insecure=insecure,
                           secret=token)
    return fetch


def write_json(document, path):
    """Write the report as JSON and return the path."""
    _make_parent(path)
    with io.open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=1, sort_keys=True)
    return path


def write_csv(document, path):
    """Write the report as CSV and return the path.

    newline="" is not decoration. Without it the csv module's own carriage
    return meets the one the text layer adds on Windows, and every other line
    of the file is blank, which Excel reads as an empty row between findings.
    """
    _make_parent(path)
    with io.open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_FIELDS)
        for row in csv_rows(document):
            writer.writerow(row)
    return path


def verdict(total, failed):
    """The self-test footer as (lines, exit code). Pure, so it can be tested."""
    if failed:
        lines = ["%d assertions, %d failed" % (total, len(failed))]
        lines.extend("  FAILED: %s" % label for label in failed)
        return lines, 1
    return ["%d assertions, 0 failed" % total], 0


def _make_parent(path):
    """Create the directory the output file goes in, when it is missing."""
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)


# ------------------------------------------------------------------ self-test

def self_test():
    """Assertions over the reconcile core. No server, no network, no tokens."""
    import shutil
    import tempfile

    passed = [0]
    failed = []

    def check(cond, label):
        if cond:
            passed[0] += 1
            print("PASS  %s" % label)
        else:
            failed.append(label)
            print("FAIL  %s" % label)

    def raises(fn, label):
        try:
            fn()
        except ValueError:
            check(True, label)
        except Exception as exc:
            check(False, "%s (wrong exception %r)" % (label, exc))
        else:
            check(False, "%s (no error raised)" % label)

    def refuses_enum(fn, label):
        """An enumeration that must refuse. Returns the refusal message."""
        try:
            fn()
        except EnumerationIncomplete as exc:
            check(True, label)
            return "%s" % exc
        except Exception as exc:
            check(False, "%s (wrong exception %r)" % (label, exc))
        else:
            check(False, "%s (returned a list instead)" % label)
        return ""

    def fails(fn, label):
        """A call that must raise RuntimeError. Returns the redacted message."""
        try:
            fn()
        except EnumerationIncomplete as exc:
            check(False, "%s (refused the enumeration instead: %s)"
                  % (label, exc))
        except RuntimeError as exc:
            check(True, label)
            return "%s" % exc
        except Exception as exc:
            check(False, "%s (wrong exception %r)" % (label, exc))
        else:
            check(False, "%s (no error raised)" % label)
        return ""

    def refuses(argv, label):
        """argparse writes usage to stderr, swallowed so a pass prints only
        PASS lines."""
        noise, sys.stderr = sys.stderr, io.StringIO()
        try:
            _parse(argv)
        except SystemExit:
            check(True, label)
        else:
            check(False, "%s (argparse accepted it)" % label)
        finally:
            sys.stderr = noise

    def same(left, right, label):
        """Two urls that must reconcile to one key."""
        try:
            lk, rk = service_key(left), service_key(right)
        except ValueError as exc:
            check(False, "%s (a url was refused: %s)" % (label, exc))
            return
        # The keys go in the label only when they differ. A passing line
        # reads as the case it covers; a failing one has to show its working.
        check(lk == rk, label if lk == rk else "%s (%s vs %s)" % (label, lk, rk))

    def differ(left, right, label):
        """Two urls that must NOT reconcile to one key."""
        try:
            lk, rk = service_key(left), service_key(right)
        except ValueError as exc:
            check(False, "%s (a url was refused: %s)" % (label, exc))
            return
        check(lk != rk, label if lk != rk else "%s (both keyed %s)"
              % (label, lk))

    print("ghostsvc self-test: no server, no portal, no network, no token")
    print("-" * 68)

    DAY = DAY_MS
    BASE = 1577836800000                   # 2020-01-01T00:00:00Z, epoch ms
    NOW = BASE + 800 * DAY
    PORTAL = "https://portal.example.org/portal"
    SERVER = "https://gis.example.org/arcgis"
    REST = SERVER + "/rest/services"

    # ---- url normalisation, which is the whole tool
    check(service_key(REST + "/Roads/MapServer") == "gis/roads/MapServer",
          "a plain rest url keys to host, folder-less name and type")
    check(service_key(REST + "/Transport/Roads/MapServer")
          == "gis/transport/roads/MapServer",
          "a service in a folder keeps the folder in its key")
    same(REST + "/Roads/MapServer", "http://gis.example.org/arcgis/rest/"
         "services/Roads/MapServer",
         "http and https are the same service  <-- pinned defect")
    same(REST + "/Roads/MapServer", "https://gis/arcgis/rest/services/Roads/"
         "MapServer",
         "a short host and its fully qualified name are one machine  "
         "<-- pinned defect")
    same(REST + "/Roads/MapServer",
         "https://GIS.EXAMPLE.ORG/arcgis/rest/services/Roads/MapServer",
         "an upper case host is the same host")
    same(REST + "/Roads/MapServer",
         "https://gis.example.org/server/rest/services/Roads/MapServer",
         "an /arcgis web adaptor and a /server one front the same service  "
         "<-- pinned defect")
    same(REST + "/Roads/MapServer",
         "https://gis.example.org/rest/services/Roads/MapServer",
         "a url with no web adaptor path at all still keys the same")
    same(REST + "/Roads/MapServer", REST + "/Roads/MapServer/",
         "a trailing slash is not a different service  <-- pinned defect")
    same(REST + "/Roads/MapServer",
         "https://gis.example.org/arcgis/rest//services/Roads/MapServer",
         "a doubled slash from a url built by concatenation keys the same")
    same(REST + "/Roads/MapServer",
         "https://gis.example.org:6443/arcgis/rest/services/Roads/MapServer",
         "an explicit :6443 is the same service as the adaptor in front of it  "
         "<-- pinned defect")
    same(REST + "/Roads/MapServer",
         "https://gis.example.org:443/arcgis/rest/services/Roads/MapServer",
         "an explicit :443 is the default https port and carries no meaning")
    same("http://gis.example.org:80/arcgis/rest/services/Roads/MapServer",
         REST + "/Roads/MapServer",
         "an explicit :80 on http keys the same too")
    same("http://gis.example.org:6080/arcgis/rest/services/Roads/MapServer",
         REST + "/Roads/MapServer",
         "and so does :6080, ArcGIS Server's own http port")
    same(REST + "/Roads/MapServer",
         "https://gis.example.org/arcgis/admin/services/Roads.MapServer",
         "the admin catalog's Name.Type spelling meets the rest catalog's "
         "Name/Type  <-- pinned defect")
    same(REST + "/Transport/Roads/MapServer",
         "https://gis.example.org/arcgis/admin/services/Transport/"
         "Roads.MapServer",
         "an admin url inside a folder meets its rest url too")
    same(REST + "/Roads/MapServer", REST + "/roads/mapserver",
         "case in the folder and service name is folded, because an item says "
         "roads/MapServer where the catalog says Roads/MapServer  "
         "<-- pinned defect")
    same(REST + "/Transport/Roads/MapServer", REST + "/TRANSPORT/roads/"
         "MAPSERVER",
         "which covers the folder as well as the service name")
    same(REST + "/Roads/MapServer", REST + "/Roads/MapServer/3",
         "a portal item pointing at layer 3 is an item for that map service  "
         "<-- pinned defect")
    same(REST + "/Roads/FeatureServer", REST + "/Roads/FeatureServer/0/",
         "a layer index with a trailing slash is dropped as well")
    same(REST + "/Roads/MapServer?f=json&token=LIVE-TOKEN",
         REST + "/Roads/MapServer",
         "a query string is not part of the key, which is what keeps a token "
         "out of it  <-- pinned defect")
    same(REST + "/Roads/MapServer#layers", REST + "/Roads/MapServer",
         "and neither is a fragment")
    same("https://gis_admin:hunter2@gis.example.org/arcgis/rest/services/"
         "Roads/MapServer", REST + "/Roads/MapServer",
         "a url carrying inline credentials keys to the service without them  "
         "<-- pinned defect")
    same("gis.example.org/arcgis/rest/services/Roads/MapServer",
         REST + "/Roads/MapServer",
         "a url typed without its scheme is still keyed")
    same("  " + REST + "/Roads/MapServer  ", REST + "/Roads/MapServer",
         "surrounding whitespace is stripped")
    # Every variant at once, which is the case the reconcile actually meets.
    same("http://GIS:6443/server/rest//services/TRANSPORT/roads/mapserver/2/",
         REST + "/Transport/Roads/MapServer",
         "all eight differences at once still reconcile to one key  "
         "<-- pinned defect")

    # Pairs that must NOT collapse. A key that merges two real services hides
    # every ghost on the second one, which is the failure a normaliser that is
    # too eager produces.
    differ(REST + "/Roads/MapServer", REST + "/Roads/FeatureServer",
           "a map service and a feature service of the same name are two "
           "services  <-- pinned defect")
    differ(REST + "/Roads/MapServer", REST + "/Transport/Roads/MapServer",
           "the same service name in a folder and at the root are two services")
    differ(REST + "/Roads/MapServer", REST + "/Rails/MapServer",
           "two different service names are two services")
    differ(REST + "/Transport/Roads/MapServer",
           REST + "/Utilities/Roads/MapServer",
           "the same service name in two folders is two services")
    differ(REST + "/Roads/MapServer",
           "https://gis2.example.org/arcgis/rest/services/Roads/MapServer",
           "two federated servers each holding a Roads/MapServer are two "
           "services  <-- pinned defect")
    differ("https://10.0.0.5/arcgis/rest/services/Roads/MapServer",
           "https://10.0.0.6/arcgis/rest/services/Roads/MapServer",
           "two servers on address literals stay apart, because shortening "
           "10.0.0.5 to its first label would make them both '10'  "
           "<-- pinned defect")
    differ(REST + "/Roads/MapServer",
           "https://gis.example.org:8443/arcgis/rest/services/Roads/MapServer",
           "a non-default port is kept, because a second site on :8443 is a "
           "second service and merging it would hide a ghost  "
           "<-- pinned defect")
    check(service_key("https://gis.example.org:8443/arcgis/rest/services/"
                      "Roads/MapServer") == "gis:8443/roads/MapServer",
          "and that port is visible in the key an operator reads")
    differ("https://[2001:db8::1]/arcgis/rest/services/Roads/MapServer",
           "https://[2001:db8::2]/arcgis/rest/services/Roads/MapServer",
           "two IPv6 literals stay apart as well")
    check(service_key("https://[2001:db8::1]/arcgis/rest/services/Roads/"
                      "MapServer") == "2001:db8::1/roads/MapServer",
          "an IPv6 host keys whole, without the brackets urlsplit removes")

    # Urls that cannot be keyed at all. Refused rather than guessed, because a
    # guessed key is a ghost that does not exist.
    raises(lambda: service_key(""), "an empty url is refused")
    raises(lambda: service_key(None), "a missing url is refused")
    raises(lambda: service_key("   "), "a whitespace-only url is refused")
    raises(lambda: service_key("https://portal.example.org/portal/home/"
                               "item.html?id=abc"),
           "a portal item page is not a service url and is refused  "
           "<-- pinned defect")
    raises(lambda: service_key(REST),
           "the catalog root names no service and is refused")
    raises(lambda: service_key(REST + "/Roads"),
           "a service url with no type is refused")
    raises(lambda: service_key(REST + "/Roads/NotAServer"),
           "a url ending in something that is not an ArcGIS service type is "
           "refused  <-- pinned defect")
    raises(lambda: service_key(REST + "/Transport/Roads.Backup"),
           "a dotted last segment whose suffix is not a service type is NOT "
           "read as the admin Name.Type spelling, it is refused  "
           "<-- pinned defect")
    raises(lambda: service_key("/arcgis/rest/services/Roads/MapServer"),
           "a relative url names no host and is refused rather than keyed to "
           "an empty host that matches nothing  <-- pinned defect")
    raises(lambda: service_key("https://gis.example.org:notaport/arcgis/rest/"
                               "services/Roads/MapServer"),
           "a port that is not a number is refused with the url in the error")
    raises(lambda: service_key(REST + "/Roads/MapServer/0/query"),
           "a query endpoint under a service is refused, because it is not "
           "the service the catalog lists")
    raises(lambda: service_key(REST + "/MapServer"),
           "a url naming a type with no service name before it is refused "
           "rather than keyed to an empty name that matches every folder  "
           "<-- pinned defect")
    raises(lambda: service_key(REST + "/MapServer/3"),
           "and so is the same url once its layer index is dropped, which is "
           "the shape that reaches the length check second  <-- pinned defect")
    check(keyed(REST + "/Roads/MapServer") == "gis/roads/MapServer",
          "keyed() gives the key for a url it can read")
    check(keyed("not a url") is None,
          "and None for one it cannot, so a caller can count it instead of "
          "catching")
    check(keyed(None) is None, "keyed() of nothing is None")

    check(sanitize_url("https://x/y?token=LIVE#top") == "https://x/y",
          "sanitize_url drops the query string and the fragment  "
          "<-- pinned defect")
    check(sanitize_url("https://x/y#token=LIVE") == "https://x/y",
          "the fragment goes FIRST, so a token carried after a hash is gone "
          "before the question mark is looked for  <-- pinned defect")
    check(sanitize_url("") == "", "sanitize_url of an empty url is empty")
    check(sanitize_url(None) == "", "sanitize_url of None is empty")
    check(sanitize_url("https://x/y") == "https://x/y",
          "a url with nothing to strip is left alone")
    check(_short_host("") == "", "an empty host shortens to nothing")
    check(_short_host("gis") == "gis", "a host with no domain is already short")
    check(_short_host("2001:db8::1") == "2001:db8::1",
          "an IPv6 literal is not shortened either")
    check(_short_host("::ffff:10.0.0.5") == "::ffff:10.0.0.5",
          "an IPv4-mapped IPv6 literal is recognised by its colons, not by "
          "its dots, which would otherwise shorten it to '::ffff:10'  "
          "<-- pinned defect")
    check(_short_host("10.0.0.5") == "10.0.0.5",
          "an IPv4 literal is not shortened  <-- pinned defect")
    check(_short_host("2020.example.org") == "2020",
          "a hostname whose first label is digits is still shortened, because "
          "it is not an address")
    check(_split_path("//a//b/") == ["a", "b"],
          "empty path segments are dropped")
    # ArcGIS Server accepts only letters, digits and underscores in a service
    # or folder name, so a non-ascii name is not a case this tool has to
    # reconcile. It still must not raise: a url read out of a portal item can
    # hold anything, and a UnicodeError here would abandon the whole run.
    cedilla = chr(0x00e7) + "ao"
    check(service_key(REST + "/" + cedilla.upper() + "/MapServer")
          == service_key(REST + "/" + cedilla + "/MapServer")
          == "gis/" + cedilla + "/MapServer",
          "a non-ascii folder name folds case like any other and keys through "
          "instead of raising  <-- pinned defect")
    check(service_key(REST + "/" + chr(0x00f1) + "/MapServer")
          != service_key(REST + "/n" + chr(0x0303) + "/MapServer"),
          "the composed and decomposed spellings of one letter stay APART: no "
          "unicode normalisation is done, and ArcGIS forbids the names where "
          "it would matter")
    check(service_key("https://gis.example.org/proxy/arcgis/rest/services/"
                      "a/rest/services/Roads/MapServer")
          == "gis/roads/MapServer",
          "the LAST rest/services wins, so a reverse proxy mounting the "
          "adaptor under a path of its own still keys the service  "
          "<-- pinned defect")

    # ---- the server catalog walk
    def catalog(tree):
        """A stand-in catalog answering from {folder: response}."""
        asked = []

        def fetch(folder):
            asked.append(folder)
            if folder not in tree:
                raise RuntimeError("no such folder %r" % folder)
            return tree[folder]
        fetch.asked = asked
        return fetch

    def rest_listing(folders, services, folder=""):
        return {"folders": list(folders),
                "services": [{"name": ("%s/%s" % (folder, n) if folder else n),
                              "type": t} for n, t in services]}

    flat = catalog({"": rest_listing([], [("Roads", "MapServer"),
                                          ("Parcels", "FeatureServer")])})
    found = walk_catalog(flat, SERVER)
    check(len(found) == 2, "a flat catalog gives both of its services")
    check(found[0]["name"] == "Roads" and found[0]["type"] == "MapServer",
          "a service record carries its name and type")
    check(found[0]["folder"] == "", "a root service has no folder")
    check(found[0]["url"] == REST + "/Roads/MapServer",
          "and the rest url built from the server root")
    check(found[0]["key"] == "gis/roads/MapServer",
          "and the key the reconcile joins on")
    check(flat.asked == [""], "a flat catalog is one request")
    accented = "Caf" + chr(0xe9)
    odd = catalog({
        "": rest_listing([accented, "My Folder"], []),
        accented: rest_listing([], [("Roads", "MapServer")], accented),
        "My Folder": rest_listing([], [("Roads", "MapServer")], "My Folder"),
    })
    check(sorted(svc["url"] for svc in walk_catalog(odd, SERVER))
          == [REST + "/Caf%C3%A9/Roads/MapServer",
              REST + "/My%20Folder/Roads/MapServer"],
          "a folder with a space or a non-ASCII letter is walked and its "
          "services get percent-encoded urls, so it neither stops the run nor "
          "goes unprobed")
    check(_quoted_path("Caf" + chr(0xe9) + "/x y?#") == "Caf%C3%A9/x%20y%3F%23",
          "a catalog path is encoded one segment at a time, and ? and # never "
          "reach the request as syntax")

    nested = catalog({
        "": rest_listing(["Transport", "Utilities"], [("Roads", "MapServer")]),
        "Transport": rest_listing([], [("Rail", "MapServer")], "Transport"),
        "Utilities": rest_listing([], [("Water", "FeatureServer")],
                                  "Utilities"),
    })
    walked = walk_catalog(nested, SERVER)
    check(len(walked) == 3, "folders are walked, not just the root  "
                            "<-- pinned defect")
    check(sorted(s["key"] for s in walked)
          == ["gis/roads/MapServer", "gis/transport/rail/MapServer",
              "gis/utilities/water/FeatureServer"],
          "and every service comes back keyed under its folder")
    check(sorted(nested.asked) == ["", "Transport", "Utilities"],
          "each folder was asked for exactly once")

    deep = catalog({
        "": rest_listing(["A"], []),
        "A": rest_listing(["B"], [("One", "MapServer")], "A"),
        "B": rest_listing([], [("Two", "MapServer")], "B"),
    })
    check(len(walk_catalog(deep, SERVER)) == 2,
          "a folder listed inside another folder is walked too")
    loop = catalog({"": rest_listing(["self"], []),
                    "self": rest_listing(["self", ""], [("X", "MapServer")],
                                         "self")})
    check(len(walk_catalog(loop, SERVER)) == 1,
          "a folder that lists itself is visited once, not for ever  "
          "<-- pinned defect")
    check(walk_catalog(catalog({"": {"folders": [], "services": []}}),
                       SERVER) == [],
          "a server with no services at all gives an empty list")
    raises(lambda: walk_catalog(catalog({"": {}}), SERVER),
           "a catalog response with neither key is not a listing, so it "
           "raises instead of reading as an empty server  <-- pinned defect")
    check(walk_catalog(catalog({"": {"folders": None, "services": None}}),
                       SERVER) == [],
          "and null folders and services are read as empty")
    blank = catalog({"": rest_listing(["", "  ", "/"], [])})
    check(walk_catalog(blank, SERVER) == [] and blank.asked == [""],
          "an empty folder name in the listing is skipped rather than asked "
          "for as the root again")
    raises(lambda: walk_catalog(catalog({"": ["not", "a", "listing"]}), SERVER),
           "a catalog answering with a JSON array raises rather than reaching "
           "body.get()  <-- pinned defect")
    raises(lambda: walk_catalog(catalog({"": {"services": ["Roads"]}}), SERVER),
           "a services entry that is a bare string raises")
    raises(lambda: walk_catalog(
        catalog({"": {"services": [{"type": "MapServer"}]}}), SERVER),
        "a service with no name raises rather than being keyed as an empty "
        "name")
    raises(lambda: walk_catalog(
        catalog({"": {"services": [{"name": "Roads"}]}}), SERVER),
        "a service with no type raises, because the type is half the key")
    # Both of those go through service_key on the way, which would refuse the
    # url anyway, so they pass whether or not service_record checks anything.
    # Asked here with no root, where no url is built and the guard in
    # service_record is the only thing between a broken catalog entry and a
    # record keyed to an empty name.
    raises(lambda: service_record({"name": "Roads"}, ""),
           "a catalog entry with no type is refused by service_record itself, "
           "not merely by the url it would have built  <-- pinned defect")
    raises(lambda: service_record({"type": "MapServer"}, ""),
           "and so is one with no name  <-- pinned defect")
    check(service_record({"name": "Roads", "type": "MapServer"}, "")
          == {"folder": "", "name": "Roads", "type": "MapServer",
              "url": "", "key": ""},
          "with no root a record carries no url and no key, rather than a key "
          "built from a host it was never given")
    raises(lambda: walk_catalog(flat, SERVER, max_folders=0),
           "a folder budget of zero raises")
    fails(lambda: walk_catalog(catalog({"": rest_listing(["Missing"], [])}),
                               SERVER),
          "the stand-in catalog refuses a folder it was never given, rather "
          "than answering an empty listing for it  <-- pinned defect")
    runaway = refuses_enum(
        lambda: walk_catalog(
            catalog({"": rest_listing(["A"], []),
                     "A": rest_listing(["B"], [], "A"),
                     "B": rest_listing(["C"], [], "B"),
                     "C": rest_listing([], [], "C")}),
            SERVER, max_folders=2),
        "a catalog deeper than --max-folders refuses instead of walking on  "
        "<-- pinned defect")
    check("gave up after 2 folder(s)" in runaway,
          "and the refusal says how many folders it visited")
    # The budget boundary, both sides of it. A walk that visits exactly the
    # budget finishes; the folder after it is the one that refuses. An
    # off-by-one here turns --max-folders into a number that means one more
    # than it says, and the runaway it exists to stop runs one level deeper.
    four = {"": rest_listing(["A"], []),
            "A": rest_listing(["B"], [], "A"),
            "B": rest_listing([], [("Rail", "MapServer")], "B")}
    check([s["key"] for s in walk_catalog(catalog(four), SERVER,
                                          max_folders=3)]
          == ["gis/b/rail/MapServer"],
          "a walk of exactly --max-folders folders finishes and returns its "
          "services  <-- pinned defect")
    refuses_enum(lambda: walk_catalog(catalog(four), SERVER, max_folders=2),
                 "one folder past the budget is the one that refuses, so the "
                 "budget means the number it says  <-- pinned defect")

    admin_tree = catalog({
        "": {"folders": ["Transport"],
             "services": [{"serviceName": "Roads", "type": "MapServer"}]},
        "Transport": {"folders": [],
                      "services": [{"serviceName": "Rail", "type": "MapServer",
                                    "folderName": "Transport"}]},
    })
    from_admin = walk_catalog(admin_tree, SERVER)
    check(sorted(s["key"] for s in from_admin)
          == ["gis/roads/MapServer", "gis/transport/rail/MapServer"],
          "the admin catalog's serviceName and folderName give the same keys "
          "as the rest catalog  <-- pinned defect")
    check(all(s["url"].startswith(REST) for s in from_admin),
          "and the url reported is always the REST one, because nobody "
          "without an admin token can open an admin url  <-- pinned defect")

    check(service_record({"name": "Roads", "type": "MapServer"}, "")["url"]
          == "", "a service record built with no root carries no url")
    check(service_record({"name": "A/B", "type": "MapServer"}, "")["folder"]
          == "A",
          "a rest name of Folder/Service puts the folder where it belongs")
    check(service_record({"name": "A/B", "type": "MapServer"}, "")["name"]
          == "B", "and leaves the bare service name behind")
    check(service_record({"serviceName": "B", "type": "MapServer",
                          "folderName": "A"}, "")["folder"] == "A",
          "an admin folderName wins over the folder being walked")
    check(service_record({"name": "B", "type": "MapServer"}, "A")["folder"]
          == "A",
          "and the folder being walked is used when the entry does not say")
    check(service_record({"name": "B", "type": "MapServer"}, "/A/")["folder"]
          == "A", "a folder name arriving with slashes is trimmed")
    check(service_url(SERVER + "/", {"folder": "", "name": "R",
                                     "type": "MapServer"})
          == REST + "/R/MapServer",
          "a server root with a trailing slash does not double it")
    check(service_url(SERVER + "?token=T", {"folder": "", "name": "R",
                                            "type": "MapServer"})
          == REST + "/R/MapServer",
          "and a token on the server root does not reach the service url  "
          "<-- pinned defect")
    check(server_root(SERVER) == SERVER, "a plain server root is left alone")
    check(server_root(SERVER + "/rest/services") == SERVER,
          "a rest catalog url is trimmed back to the deployment root")
    check(server_root(SERVER + "/admin/services/") == SERVER,
          "so is an admin catalog url with a trailing slash")
    check(server_root(SERVER + "/REST/Services") == SERVER,
          "and the trim is case-insensitive, because the url is")
    check(server_root(SERVER + "/rest") == SERVER, "as is a bare /rest")
    check(server_root(SERVER + "/admin") == SERVER, "and a bare /admin")

    # ---- the anonymity verdict, which is the audit deliverable
    live = {"currentVersion": 11.2, "serviceDescription": "Roads"}
    check(is_anonymous(200, live)[0] is True,
          "a service description returned with no token is ANONYMOUS  "
          "<-- pinned defect")
    check("currentVersion" in is_anonymous(200, live)[1],
          "and the verdict says what proved it")
    check(is_anonymous(200, {"layers": [], "tables": []})[0] is True,
          "a feature service listing its layers is anonymous too")
    check(is_anonymous(200, {"capabilities": "Query"})[0] is True,
          "so is one that only reports its capabilities")
    check(is_anonymous(200, {"serviceDataType": "esriImageServiceDataTypeRGB"})[0]
          is True, "and an image service reporting its data type")
    denied = is_anonymous(200, {"error": {"code": 499,
                                          "message": "Token Required"}})
    check(denied[0] is False,
          "a 200 carrying Token Required is NOT anonymous, which is how "
          "ArcGIS says no  <-- pinned defect")
    check("499" in denied[1] and "Token Required" in denied[1],
          "and the refusal carries the server's own code and message")
    check(is_anonymous(200, {"error": {"code": 403, "message": "Forbidden"}})[0]
          is False, "a 200 carrying 403 Forbidden is not anonymous either")
    check(is_anonymous(403, None)[0] is False, "an HTTP 403 is not anonymous")
    check(is_anonymous(401, None)[1] == "HTTP 401",
          "an HTTP 401 says so in the reason")
    check(is_anonymous(302, None)[0] is False,
          "a redirect is not proof of anything")
    login = is_anonymous(200, None)
    check(login[0] is False,
          "an HTTP 200 whose body is not JSON is NOT anonymous, because that "
          "is what an IWA or SAML login page looks like from here  "
          "<-- pinned defect")
    check("login page" in login[1],
          "and the reason names the login page, which is the thing an "
          "operator has to go and look at")
    check(is_anonymous(200, ["a", "list"])[0] is False,
          "a JSON array is not a service description")
    check(is_anonymous(200, {"folders": [], "services": []})[0] is False,
          "a catalog listing is not a service description, so a probe that "
          "landed on the wrong url is not counted as anonymous  "
          "<-- pinned defect")
    check(is_anonymous(200, {})[0] is False,
          "an empty object proves nothing")
    check(is_anonymous(0, None, "timed out")[0] is False,
          "a service that did not answer at all is not anonymous")
    check(is_anonymous(0, None, "timed out")[1] == "timed out",
          "and the transport error is the reason")
    check(is_anonymous(200, live, "timed out")[0] is False,
          "a transport error wins over a body, because the body cannot have "
          "come from a request that failed")
    check(is_anonymous("200", live)[0] is True,
          "a status that arrived as a string is still read as 200")

    # ---- probing every service
    catalogue = [
        {"key": "gis/open/MapServer", "url": REST + "/Open/MapServer",
         "folder": "", "name": "Open", "type": "MapServer"},
        {"key": "gis/shut/MapServer", "url": REST + "/Shut/MapServer",
         "folder": "", "name": "Shut", "type": "MapServer"},
    ]

    def canned_probe(url, insecure, timeout):
        canned_probe.seen.append((url, insecure, timeout))
        if "Open" in url:
            return 200, live, None
        return 200, {"error": {"code": 499, "message": "Token Required"}}, None
    canned_probe.seen = []

    anon, why = probe_all(catalogue, probe=canned_probe)
    check(anon == set(["gis/open/MapServer"]),
          "only the service that answered is reported anonymous")
    check("currentVersion" in why["gis/open/MapServer"],
          "the reason for the open one is what it answered with")
    check("Token Required" in why["gis/shut/MapServer"],
          "and the closed one keeps the server's refusal as its reason")
    check(len(canned_probe.seen) == 2, "every service was probed")
    check(not any("token" in url for url, _i, _t in canned_probe.seen),
          "no probe url carries a token, which is the whole experiment  "
          "<-- pinned defect")
    echoed = []
    probe_all(catalogue, echo=echoed.append, probe=canned_probe)
    check(len(echoed) == 1 and "ANONYMOUS" in echoed[0],
          "the progress echo names each anonymous service as it is found")
    check(probe_all([], probe=canned_probe) == (set(), {}),
          "probing an empty catalog asks nothing")
    for status, body, error, want, label in (
            (0, None, "refused", False, "a transport error is not an answer"),
            (401, None, None, True, "an HTTP 401 is a refusal"),
            (403, None, None, True, "an HTTP 403 is a refusal"),
            (500, None, None, False, "an HTTP 500 leaves the question open"),
            (404, None, None, False, "an HTTP 404 leaves the question open"),
            (200, None, None, True, "a login page is a refusal"),
            (200, {"error": {"code": 499, "message": "Token Required"}},
             None, True, "a 200 asking for a token is a refusal"),
            (200, {"error": {"code": 500, "message": "not started"}},
             None, False, "a 200 carrying some other error is not a refusal"),
            (200, {"currentVersion": 11.2}, None, True,
             "a service description is a definite answer"),
            (200, {"folders": []}, None, False,
             "a catalog listing is no answer to a probe")):
        check(probe_conclusive(status, body, error) is want,
              "probe_conclusive: %s  <-- pinned defect" % label)

    def mixed_probe(url, insecure, timeout):
        if "Open" in url:
            return 200, live, None
        return 0, None, "[Errno 111] Connection refused"
    gone = set()
    probe_all(catalogue, probe=mixed_probe, unanswered=gone)
    check(gone == set(["gis/shut/MapServer"]),
          "probe_all names the services it could not ask  <-- pinned defect")

    # ---- the reconcile itself
    def svc(name, folder="", stype="MapServer", host="gis.example.org"):
        url = "https://%s/arcgis/rest/services/%s%s/%s" % (
            host, folder + "/" if folder else "", name, stype)
        return {"folder": folder, "name": name, "type": stype, "url": url,
                "key": service_key(url)}

    def item(iid, url, title=None, owner="jsmith", itype="Map Service",
             access="org"):
        return {"id": iid, "title": title or iid, "owner": owner,
                "type": itype, "access": access, "url": url}

    roads = svc("Roads")
    rail = svc("Rail", "Transport")
    water = svc("Water", "Utilities", "FeatureServer")

    clean = reconcile([roads], [item("i1", REST + "/Roads/MapServer")])
    check(clean.findings == [], "a service with an item is no finding at all")
    check(clean.matched == 1, "and it counts as matched")
    check(exit_code(clean) == 0, "a clean reconcile exits 0")
    check(repr(clean).startswith("Report(0 finding(s)"),
          "a report reprs with its counts")

    # The url the portal holds is almost never the one the catalog builds.
    spelled = reconcile([roads], [item(
        "i1", "http://GIS:6443/server/rest//services/roads/mapserver/0/")])
    check(spelled.findings == [],
          "an item whose url differs by scheme, host, adaptor, port, case, a "
          "doubled slash, a layer index and a trailing slash still matches its "
          "service  <-- pinned defect")

    public_url = "https://maps.example.net/arcgis/rest/services/Roads/MapServer"
    split = reconcile([roads], [item("i1", public_url)])
    check(sorted(f.kind for f in split.findings) == ["ghost", "orphan"],
          "an item registered under a public host name reads as an orphan "
          "beside a ghost, which is why --host-alias exists")
    amap = parse_host_aliases(["Maps.Example.NET = gis.example.org"])
    check(amap == {"maps.example.net": "gis.example.org"},
          "--host-alias pairs are parsed, trimmed and lowercased")
    check(parse_host_aliases([]) == {} and parse_host_aliases(None) == {},
          "and no pair at all is an empty map")
    joined = reconcile([roads], [item("i1", public_url)], aliases=amap)
    check(joined.findings == [] and joined.matched == 1,
          "an aliased item matches the service on the server host, so the "
          "ghost and the orphan both go")
    check(joined.items[0]["url"] == public_url,
          "and the item keeps the url it has, because the alias is used for "
          "matching only")
    other = reconcile([roads], [item("i1", public_url)],
                      aliases={"maps.example.net": "gis.other.org"})
    check(sorted(f.kind for f in other.findings) == ["ghost", "orphan"],
          "an alias to a host in another domain does not match a service "
          "there")
    check(alias_url(public_url, amap) == REST + "/Roads/MapServer",
          "alias_url swaps the host and keeps the path")
    check(alias_url("http://MAPS.example.net.:6443/x/y", amap)
          == "http://gis.example.org:6443/x/y",
          "keeps the port and the scheme, and ignores case and a trailing "
          "dot")
    check(alias_url("maps.example.net/x", amap) == "https://gis.example.org/x",
          "a url with no scheme gets https")
    check(alias_url("https://other.example.net/x", amap)
          == "https://other.example.net/x",
          "a host with no alias is returned as it was")
    check(alias_url(public_url, {}) == public_url
          and alias_url(None, amap) is None and alias_url("", amap) == "",
          "no alias map, no url and an empty url are returned as they were")
    check(alias_url("https://maps.example.net:abc/x", amap)
          == "https://maps.example.net:abc/x",
          "a url with a port that is not a number is returned as it was")
    for bad_pair in ("nonsense", "a=b/c", "=x", "x=", "https://a=b",
                     "u:PW@h=x"):
        refused = ""
        try:
            parse_host_aliases([bad_pair])
        except ValueError as exc:
            refused = "%s" % exc
        check(bool(refused) and "PW" not in refused,
              "a --host-alias of %r is refused, and a credential in it is not "
              "echoed" % bad_pair)

    ghost = reconcile([roads, rail], [item("i1", REST + "/Roads/MapServer")])
    check(len(ghost.findings) == 1 and ghost.findings[0].kind == "ghost",
          "a running service with no portal item is a GHOST  "
          "<-- pinned defect")
    check(ghost.findings[0].key == "gis/transport/rail/MapServer",
          "and the finding names the service, not the item")
    check(ghost.findings[0].url == rail["url"],
          "with the url somebody can paste into a browser")
    check(ghost.findings[0].items == [],
          "a ghost has no items, because that is what makes it one")
    check(ghost.matched == 1, "the other service still counts as matched")
    check(exit_code(ghost) == 1, "a reconcile with findings exits 1")

    orphan = reconcile([roads], [item("i1", REST + "/Roads/MapServer"),
                                 item("i2", REST + "/Gone/MapServer")])
    check(len(orphan.findings) == 1 and orphan.findings[0].kind == "orphan",
          "a portal item whose service is not in the catalog is an ORPHAN  "
          "<-- pinned defect")
    check(orphan.findings[0].items[0]["id"] == "i2",
          "and the finding names the item")
    check(orphan.findings[0].service is None,
          "an orphan has no service, because that is what makes it one")
    check(orphan.findings[0].url == REST + "/Gone/MapServer",
          "an orphan reports the url the item claims")

    both = reconcile([roads, rail], [item("i1", REST + "/Roads/MapServer"),
                                     item("i2", REST + "/Gone/MapServer")])
    check(sorted(f.kind for f in both.findings) == ["ghost", "orphan"],
          "a ghost and an orphan in one org are two separate findings")
    check(both.findings[0].kind == "ghost",
          "and the ghost is listed first, because it is the one that is "
          "serving data right now  <-- pinned defect")

    exposed = reconcile([roads], [item("i1", REST + "/Roads/MapServer")],
                        anonymous=["gis/roads/MapServer"],
                        details={"gis/roads/MapServer": "answered"})
    check(len(exposed.findings) == 1
          and exposed.findings[0].kind == "anonymous",
          "a service that answers anonymously is a finding even though it has "
          "an item  <-- pinned defect")
    check(exposed.findings[0].items[0]["id"] == "i1",
          "and the item it does have is reported with it")
    check(exposed.findings[0].detail == "answered",
          "the probe's reason is carried into the finding")
    check(exposed.matched == 0,
          "a flagged service does not count as quietly matched")

    disaster = reconcile([roads, rail], [item("i1", REST + "/Roads/MapServer")],
                         anonymous=["gis/transport/rail/MapServer"])
    check(disaster.findings[0].kind == "anonymous-ghost",
          "a service that answers anonymously AND has no item is the headline "
          "finding  <-- pinned defect")
    check(disaster.findings[0].severity == 100,
          "and it outranks everything else")
    check(len(disaster.ghosts) == 1 and len(disaster.anonymous) == 1,
          "it counts once as a ghost and once as anonymous, because it is "
          "both")
    check(disaster.findings[0].anonymous is True,
          "the finding says it is anonymous without the caller parsing its "
          "kind")

    ranked = reconcile(
        [roads, rail, water],
        [item("i1", REST + "/Roads/MapServer"),
         item("i2", REST + "/Gone/MapServer")],
        anonymous=["gis/roads/MapServer", "gis/transport/rail/MapServer"])
    check([f.kind for f in ranked.findings]
          == ["anonymous-ghost", "anonymous", "ghost", "orphan"],
          "findings are ranked worst first: anonymous ghost, anonymous, "
          "ghost, orphan  <-- pinned defect")
    check([f.severity for f in ranked.findings] == [100, 80, 50, 20],
          "and each kind carries its own severity")

    twins = reconcile([roads], [item("i1", REST + "/Roads/MapServer"),
                                item("i2", REST + "/Roads/MapServer/0")])
    check(twins.findings == [],
          "two items pointing at one service are not a ghost and not an "
          "orphan")
    check(twins.matched == 1, "and the service is matched once, not twice")
    shared = reconcile([roads], [item("i1", REST + "/Roads/MapServer"),
                                 item("i2", REST + "/Roads/MapServer")],
                       anonymous=["gis/roads/MapServer"])
    check(len(shared.findings) == 1 and len(shared.findings[0].items) == 2,
          "both items are listed under the one service they share")

    nothing = reconcile([], [])
    check(nothing.findings == [] and nothing.matched == 0,
          "an empty server and an empty portal reconcile to nothing")
    check(exit_code(nothing) == 0, "and that exits 0")
    no_portal = reconcile([roads, rail], [])
    check(len(no_portal.findings) == 2
          and all(f.kind == "ghost" for f in no_portal.findings),
          "an empty portal makes every service a ghost, which is why an "
          "enumeration that refuses matters  <-- pinned defect")
    no_server = reconcile([], [item("i1", REST + "/Roads/MapServer")])
    check(len(no_server.findings) == 1
          and no_server.findings[0].kind == "orphan",
          "an empty server makes every item an orphan")

    mixed = reconcile([roads], [item("i1", REST + "/Roads/MapServer"),
                                item("i2", ""),
                                item("i3", "https://portal/home/item.html")])
    check(mixed.findings == [],
          "an item with no url and an item pointing at a web page are NOT "
          "orphans, because neither claims a service  <-- pinned defect")
    check(len(mixed.unreadable) == 2,
          "they are counted as unreadable instead of being dropped in silence")
    check(sorted(r["id"] for r in mixed.unreadable) == ["i2", "i3"],
          "and the report names them")
    check(mixed.unreadable[0]["url"] in ("", "https://portal/home/item.html"),
          "an unreadable item still carries whatever url it had")

    cross = reconcile([svc("Roads", host="gis.example.org"),
                       svc("Roads", host="gis2.example.org")],
                      [item("i1", "https://gis2/arcgis/rest/services/Roads/"
                                  "MapServer")])
    check(len(cross.findings) == 1
          and cross.findings[0].key == "gis/roads/MapServer",
          "an item on the second federated server does not silence the ghost "
          "on the first  <-- pinned defect")

    # Two servers whose host names share a first label. The key folds a host
    # to that label, so the domain has to be what keeps them apart.
    alpha = svc("Roads", host="gis.alpha.example.org")
    beta = item("i1", "https://gis.beta.example.net/arcgis/rest/services/"
                      "Roads/MapServer")
    check(service_key(alpha["url"]) == service_key(beta["url"]),
          "two servers that share a first label do key alike, which is why "
          "the domain is compared as well")
    other = reconcile([alpha], [beta])
    check(sorted(f.kind for f in other.findings) == ["ghost", "orphan"],
          "an item on another domain with the same first label does not hide "
          "the ghost, and reads as an orphan  <-- pinned defect")
    check(exit_code(other) == 1, "so that run exits 1, not 0")
    check(reconcile([alpha], [item("i1", "https://gis.alpha.example.org./"
                                   "arcgis/rest/services/ROADS/MapServer")]
                    ).findings == [],
          "the same domain with a trailing dot and another case still matches")
    check(reconcile([alpha], [item("i1", "https://gis/arcgis/rest/services/"
                                         "Roads/MapServer")]).findings == [],
          "and so does the short host, which names no domain to disagree with")
    check(host_domain("https://GIS.Alpha.Example.org:6443/x")
          == "alpha.example.org", "a host's domain is everything after its "
          "first label")
    check(host_domain("https://gis/x") == "" and host_domain("") == ""
          and host_domain(None) == "",
          "a short host and no host have no domain")
    check(host_domain("https://10.0.0.5/x") == ""
          and host_domain("https://[2001:db8::1]/x") == "",
          "an address literal has no domain either")
    check(same_machine("https://gis.a.org/x", "https://gis.b.org/x") is False
          and same_machine("https://gis/x", "https://gis.b.org/x") is True
          and same_machine("https://gis.a.org/x", "https://gis.a.org/y")
          is True,
          "only two named, different domains are different machines")

    # A probe that could not ask is not a probe that was refused.
    road_key, rail_key = roads["key"], rail["key"]
    both_items = [item("i1", REST + "/Roads/MapServer"),
                  item("i2", REST + "/Transport/Rail/MapServer")]
    skipped = reconcile([roads, rail], both_items, probes={})
    check(skipped.findings == [] and skipped.probe_skipped
          and exit_code(skipped) == 0,
          "a run that skipped the probe has no finding and exits 0")
    check(any("probe was not run" in line for line in describe(skipped))
          and not any("not one of them answered" in line
                      for line in describe(skipped)),
          "but it does not say that no service answered anonymously, because "
          "nothing was asked  <-- pinned defect")
    dead = reconcile([roads, rail], both_items,
                     probes={road_key: False, rail_key: False})
    check(dead.probe_failed and dead.untested == sorted([road_key, rail_key])
          and exit_code(dead) == 2,
          "a probe that got no definite answer from any service exits 2, not "
          "0  <-- pinned defect")
    check(any("no probe got an answer" in line for line in describe(dead))
          and not any("not one of them answered" in line
                      for line in describe(dead)),
          "and says so, instead of claiming that none answered anonymously  "
          "<-- pinned defect")
    some = reconcile([roads, rail], both_items,
                     probes={road_key: True, rail_key: False})
    check(some.untested == [rail_key] and exit_code(some) == 2
          and not some.probe_failed and not some.probe_skipped,
          "one service that could not be asked, with no finding, exits 2 "
          "because it might be open to everyone  <-- pinned defect")
    check(any("1 of 2 service(s) could not be probed" in line
              for line in describe(some))
          and any("every service that could be probed refused" in line
                  for line in describe(some)),
          "and the summary names how many were left open")
    check(exit_code(reconcile([roads, rail], both_items[:1],
                              probes={road_key: True, rail_key: False})) == 1,
          "a finding still exits 1 when a probe was left open")
    full = reconcile([roads, rail], both_items,
                     probes={road_key: True, rail_key: True})
    check(full.untested == [] and exit_code(full) == 0
          and any("not one of them answered" in line
                  for line in describe(full)),
          "a run where every probe was conclusive keeps the clean sentence")
    check(exit_code(reconcile([roads], [], probes={road_key: False})) == 1,
          "a ghost is still exit 1 when its probe failed")
    open_ghost = reconcile([roads, rail], both_items[:1],
                           probes={road_key: True, rail_key: False})
    check(finding_record(open_ghost.findings[0])["anonymous"] is None,
          "a ghost whose probe could not ask is recorded as unknown, not as "
          "not anonymous  <-- pinned defect")
    check(build_report(SERVER, PORTAL, "q", "t", open_ghost)["unprobed"] == 1,
          "and the report says how many services were left unprobed")
    check(csv_rows(build_report(SERVER, PORTAL, "q", "t", open_ghost))[0][7]
          == "", "and its csv cell is empty  <-- pinned defect")
    closed_ghost = reconcile([roads, rail], both_items[:1],
                             probes={road_key: True, rail_key: True})
    check(csv_rows(build_report(SERVER, PORTAL, "q", "t", closed_ghost))[0][7]
          == "no", "a ghost that was probed and refused is still no")

    raises(lambda: Finding("nonsense", "k"),
           "a finding kind nothing knows about raises rather than sorting as "
           "harmless")
    check(repr(Finding("ghost", "k")) == "Finding('ghost', 'k')",
          "a finding reprs as its kind and key")
    # The service url is sanitized on the way out as well as on the way in.
    # A service record built here always carries a clean url, so this guard
    # is the second of two, and it is the one the report actually reads.
    dirty = Finding("ghost", "k",
                    {"url": REST + "/Roads/MapServer?token=LIVE-TOKEN",
                     "folder": "", "name": "Roads", "type": "MapServer"})
    check(dirty.url == REST + "/Roads/MapServer",
          "a finding strips a token off the service url it prints, even "
          "when the caller handed it a dirty one  <-- pinned defect")
    check("LIVE-TOKEN" not in json.dumps(finding_record(dirty)),
          "and nothing carrying that token reaches the report record")

    # ---- what reaches the report file
    kept = item_record({"id": "abc", "title": "Roads", "owner": "jsmith",
                        "type": "Map Service", "access": "public",
                        "url": REST + "/Roads/MapServer?token=LIVE-TOKEN",
                        "description": "x" * 4000})
    check(kept["id"] == "abc" and kept["access"] == "public",
          "an item record keeps what the report needs")
    check(kept["url"] == REST + "/Roads/MapServer",
          "and strips the token out of the item's url  <-- pinned defect")
    check("description" not in kept,
          "a four thousand character description does not reach the report")
    thin = item_record({"id": "abc"})
    check(thin["title"] == "" and thin["owner"] == "",
          "missing text fields become empty strings, not None")
    check(thin["access"] == "private",
          "an item with no access field is recorded private, the safe reading")
    check(thin["url"] == "", "and an item with no url records an empty url")
    check(sanitize_url("https://svc:PW@gis.example.org/arcgis?token=T#x")
          == "https://gis.example.org/arcgis",
          "a user:password@ in a url does not survive sanitising  "
          "<-- pinned defect")
    check(sanitize_url("svc:PW@gis.example.org/arcgis")
          == "gis.example.org/arcgis",
          "and neither does one on a url typed without its scheme")
    check(sanitize_url("https://gis.example.org/a@b/x")
          == "https://gis.example.org/a@b/x" and sanitize_url("") == "",
          "an @ in the path is left alone, and an empty url stays empty")
    for dirty_pw in ("Hunter/2pw", "Hun?ter", "Hun#ter", "Hu:nt@er",
                     "/", "a/b/c"):
        check(sanitize_url("http://svc:%s@gis.example.org/arcgis"
                           % dirty_pw) == "http://gis.example.org/arcgis",
              "a password holding %r is removed whole  <-- pinned defect"
              % dirty_pw)
    check(sanitize_url("gis.example.org/a?next=https://x/y")
          == "gis.example.org/a",
          "a :// inside a query string is not taken for a scheme")
    check(sanitize_url("https://h:6443/arcgis/rest?u=a@b.com&token=SECRET")
          == "https://h:6443/arcgis/rest",
          "an @ in a query parameter is not a credential separator, so the "
          "token after it is not printed  <-- pinned defect")
    check(sanitize_url("https://h/x?time=1:2&e=a@b&token=SECRET")
          == "https://h/x",
          "and a : earlier in the query does not make it one  "
          "<-- pinned defect")
    check(sanitize_url("https://u:PW@h/x?e=a@b&token=SECRET") == "https://h/x",
          "a real user:password@ is still removed beside a query @")
    check(sanitize_url("https://h:6443/x#f=1@2&token=SECRET")
          == "https://h:6443/x",
          "an @ in a fragment is read the same way  <-- pinned defect")
    check(sanitize_url("https://h:6443/arcgis/rest/services/Parcels@2024/"
                       "MapServer") == "https://2024/MapServer",
          "known limit: an @ in the path of a url that has a port is read as "
          "a credential separator and the host is cut off")
    check(item_record({"id": "x", "url": "https://u:ITEMPW@gis.example.org/"
                       "arcgis/rest/services/Old/MapServer"})["url"]
          == "https://gis.example.org/arcgis/rest/services/Old/MapServer",
          "an item url carrying a password is stored without it  "
          "<-- pinned defect")

    document = build_report(SERVER + "?token=LIVE", PORTAL, "orgid:ORG",
                            "2026-09-16T00:00:00Z", ranked)
    check(document["services"] == 3 and document["items"] == 2,
          "the document says how much was compared")
    check(document["ghosts"] == 2 and document["orphans"] == 1
          and document["anonymous"] == 2,
          "and counts each kind of finding")
    check(document["server"] == SERVER,
          "a token on the server url does not reach the document  "
          "<-- pinned defect")
    check(len(document["findings"]) == 4, "every finding is in the document")
    check(document["findings"][0]["kind"] == "anonymous-ghost",
          "in the order they were ranked")
    check(document["findings"][0]["anonymous"] is True,
          "with the anonymous verdict spelled out")
    check(json.dumps(document), "the document is JSON serialisable")

    rows = csv_rows(document)
    check(len(rows) == 4,
          "the csv has one row per finding when each has at most one item")
    check(rows[0][0] == "anonymous-ghost" and rows[0][7] == "yes",
          "and spells the anonymous column yes or no for a spreadsheet")
    check(rows[2][9] == "",
          "a ghost's item columns are empty, because it has no item")
    multi = csv_rows(build_report(SERVER, PORTAL, "q", "t", shared))
    check(len(multi) == 2,
          "a finding with two items becomes two rows, so the sheet can be "
          "sorted by item  <-- pinned defect")
    check(multi[0][2] == multi[1][2],
          "and both rows carry the same service key")
    check(all(len(row) == len(CSV_FIELDS) for row in rows + multi),
          "every csv row has every column")

    # ---- formula injection: a text cell must not be run by a spreadsheet
    LEADS = ("=", "+", "-", "@", "\t", "\r")
    check(FORMULA_LEADS == LEADS,
          "the guarded lead characters are exactly = + - @ tab and carriage "
          "return, written out here so the constant cannot shrink unseen  "
          "<-- pinned defect")
    check(all(cell(lead + "x") == "'" + lead + "x" for lead in LEADS),
          "a cell led by =, +, -, @, tab or carriage return gets one "
          "apostrophe  <-- pinned defect")
    check(cell("Hydrants") == "Hydrants" and cell("") == "",
          "ordinary text and an empty cell are untouched")
    check(cell("a=b") == "a=b" and cell("Roads-2") == "Roads-2",
          "a lead character that is not first is untouched")
    check(cell(None) == "None" and cell(-5) == "'-5",
          "a value that is not text is turned into text before it is judged")
    check(cell("=1+1") == "'=1+1" and cell(cell("=1+1")) == "'=1+1",
          "a cell already led by the apostrophe is not prefixed twice")
    injected = []
    for lead in LEADS:
        text = lead + "x"
        injected.append({
            "kind": "anonymous-ghost", "severity": 100, "key": text,
            "service_url": text, "folder": text, "name": text, "type": text,
            "anonymous": True, "detail": text,
            "items": [{"id": text, "title": text, "owner": text,
                       "type": text, "access": text}]})
    leaked = {"findings": injected}
    probe_dir = tempfile.mkdtemp(prefix="ghostsvc-formula-")
    try:
        probe_csv = write_csv(leaked, os.path.join(probe_dir, "f.csv"))
        with io.open(probe_csv, "r", encoding="utf-8", newline="") as handle:
            probe_table = list(csv.reader(handle))
    finally:
        shutil.rmtree(probe_dir, ignore_errors=True)
    check(len(probe_table) == 1 + len(LEADS),
          "six hostile findings read back as six rows under the header, so a "
          "tab or carriage return inside a cell did not split a row")
    for column in ("key", "service_url", "folder", "name", "type", "detail",
                   "item_id", "item_title", "item_owner", "item_type",
                   "item_access"):
        position = CSV_FIELDS.index(column)
        check(all(row[position] == "'" + lead + "x"
                  for row, lead in zip(probe_table[1:], LEADS)),
              "the %s column is guarded for =, +, -, @, tab and carriage "
              "return  <-- pinned defect" % column)
    check(all(row[CSV_FIELDS.index("severity")] == "100"
              and row[CSV_FIELDS.index("anonymous")] == "yes"
              and row[CSV_FIELDS.index("kind")] == "anonymous-ghost"
              for row in probe_table[1:]),
          "severity stays a plain number and kind and anonymous are untouched")

    # ---- rendering
    lines = describe(ranked)
    check(lines[0].startswith("3 service(s) on the server, 2 portal item(s)"),
          "the summary leads with what was compared")
    check(any("4 finding(s): 2 anonymous, 2 ghost(s), 1 orphan(s)" in line
              for line in lines),
          "and counts the findings by kind")
    check(any("anonymous-ghost" in line for line in lines),
          "each finding prints its kind")
    check(any(rail["url"] in line for line in lines),
          "and its url")
    check(any("[100]" in line for line in lines),
          "with the severity in front of it")
    check(any("Every service on the server has a portal item" in line
              for line in describe(clean)),
          "a clean reconcile says so instead of printing an empty list")
    check(any("no url this tool could read" in line
              for line in describe(mixed)),
          "unreadable items are reported in the summary")
    check(not any("no url this tool could read" in line for line in lines),
          "and are not mentioned when there are none")
    detailed = describe(exposed)
    check(any("answered" in line for line in detailed),
          "the probe's reason is printed under the finding it belongs to")
    check(any("i1" in line for line in detailed),
          "and the item is listed under it")
    warned = Report(ranked.findings, ranked.services, ranked.items, [],
                    ["the total moved"])
    check(any("ENUMERATION WARNINGS" in line for line in describe(warned)),
          "an enumeration that did not reconcile leads its warnings with a "
          "heading")
    check(any("may have an item after all" in line
              for line in describe(warned)),
          "and says what that does to the ghost list  <-- pinned defect")
    quiet_warned = Report([], ranked.services, ranked.items, [],
                          ["the total moved"])
    check(any("not a clean result" in line for line in describe(quiet_warned))
          and exit_code(quiet_warned) == 2,
          "a run with no finding and an enumeration warning says it is not "
          "clean and exits 2, not 0  <-- pinned defect")

    check(printable("plain", "cp1252") == "plain",
          "an ascii title passes through a cp1252 console")
    check(printable(chr(0x6c34), "cp1252") == "?",
          "a title a cp1252 console cannot encode is replaced, not crashed on "
          " <-- pinned defect")
    check(printable(chr(0x6c34), "utf-8") == chr(0x6c34),
          "a console that can encode the title gets the real title")
    check(printable("x", None) == "x", "a stream with no encoding is left alone")
    check(printable("x", "no-such-codec") == "x",
          "an encoding python has never heard of is left alone, not raised on")

    check(is_http_url("https://gis.example.org/arcgis") is True,
          "an https url is openable")
    check(is_http_url("http://gis.local/arcgis") is True,
          "a plain http url is openable")
    check(is_http_url("gis.example.org/arcgis") is False,
          "a url with no scheme is refused, because urllib quotes the whole "
          "url back into its error and that url carries the token  "
          "<-- pinned defect")
    check(is_http_url("") is False, "an empty url is refused")
    check(is_http_url(None) is False, "a missing url is refused")
    check(redact("token=SECRET1", "SECRET1") == "token=" + REDACTED,
          "a secret is removed before printing")
    check(redact("password=p%40ss+w%2Frd%261 and p%40ss%20w%2Frd%261 and "
                 "p@ss w/rd&1", "p@ss w/rd&1") == "password=%s and %s and %s"
          % (REDACTED, REDACTED, REDACTED),
          "a password the server echoes back form-encoded or percent-encoded "
          "is redacted too  <-- pinned defect")
    check(redact("a=1", None, "") == "a=1",
          "a redact with nothing to remove leaves the text alone")
    check(redact("id 7 failed", 7) == "id %s failed" % REDACTED,
          "a secret that is not a string is still removed  <-- pinned defect")
    check(utcnow().tzinfo is not None,
          "the timestamp on the report is timezone aware")

    # ---- the portal pager, which the ghost list depends on being complete
    check(clamp_num(100) == 100, "a page size of 100 is passed through")
    check(clamp_num(1000) == 100,
          "a page size of 1000 is clamped to 100 before it is sent, because "
          "the server clamps it silently  <-- pinned defect")
    check(clamp_num(1) == 1, "a page size of 1 is honoured")
    check(clamp_num(25) == 25, "a page size under the cap is left alone")
    raises(lambda: clamp_num(0), "a page size of zero raises")
    raises(lambda: clamp_num("100"), "a page size that is a string raises")
    raises(lambda: clamp_num(True),
           "a page size of True raises, rather than paging one row at a time")
    check(is_capped(10000) is True,
          "exactly 10,000 is the CAP and never a total  <-- pinned defect")
    check(is_capped(9999) is False, "9,999 is under the cap and is a real total")
    check(is_capped(0) is False, "an empty result is not capped")
    check(next_start({"nextStart": 101}, 1, 100) == 101,
          "the server's nextStart is followed")
    check(next_start({"nextStart": -1}, 101, 100) is None,
          "a nextStart of -1 ends the crawl  <-- pinned defect")
    check(next_start({"nextStart": 0}, 101, 100) is None,
          "a nextStart of 0 ends the crawl too")
    check(next_start({}, 1, 10) == 11,
          "a short page advances by the ten rows it got, not by the hundred it "
          "asked for  <-- pinned defect")
    check(next_start({}, 1, 0) is None, "a page with no rows ends the crawl")
    check(next_start({"nextStart": 10001}, 9901, 100) is None,
          "a next page starting past the 10,000 ceiling is not asked for  "
          "<-- pinned defect")
    check(next_start({"nextStart": SEARCH_CEILING}, 9801, 100)
          == SEARCH_CEILING,
          "a next page starting exactly on the ceiling is still asked for")
    raises(lambda: next_start({"nextStart": 50}, 100, 10),
           "a nextStart that goes backwards raises instead of looping for ever")
    raises(lambda: next_start({"nextStart": 100}, 100, 10),
           "a nextStart EQUAL to start raises too, because standing still "
           "reads the same page for ever  <-- pinned defect")
    raises(lambda: next_start({}, 0, 10), "a start of 0 raises, start is 1-based")
    raises(lambda: next_start({}, 1, -1), "a negative row count raises")
    check(quote_term("jsmith") == "jsmith", "a plain term needs no quotes")
    check(quote_term("Feature Service") == '"Feature Service"',
          "a term with a space is quoted")
    check(quote_term("a:b") == '"a:b"',
          "a term holding a colon is quoted, or the server reads it as a field")
    raises(lambda: quote_term(""), "an empty term raises")
    raises(lambda: quote_term("   "), "a whitespace-only term raises")
    raises(lambda: quote_term('bad"name'),
           "a term holding a double quote raises, because it would close the "
           "query early and silently select different items  <-- pinned defect")
    check(type_clause(["PDF", "CSV"]) == "type:(PDF OR CSV)",
          "a type clause ORs its terms")
    check(type_clause(["Web Map"], True) == '-type:("Web Map")',
          "a negated clause carries the leading minus and quotes the space")
    raises(lambda: type_clause([]), "an empty type clause raises")

    root = Partition("orgid:ORG", EPOCH_START_MS, NOW)
    check(partition_query(root) == "(orgid:ORG) AND created:[0 TO %d]" % NOW,
          "the root partition is the base query bounded by a date range")
    check(partition_query(Partition("", 0, 10)) == "created:[0 TO 10]",
          "an empty base query renders to the date range alone")
    check(partition_query(Partition("a OR b", 0, 10))
          == "(a OR b) AND created:[0 TO 10]",
          "the base query is parenthesised, or the date range would AND onto "
          "its last term only  <-- pinned defect")
    check(repr(Partition("", 0, 5)) == "Partition('created:[0 TO 5]')",
          "a partition reprs as the query it renders to")
    check(root.divisible() is True, "a range of 800 days can still be split")
    check(Partition("", BASE, BASE + DAY - 1).divisible() is False,
          "one day with no types left cannot be split")
    check(Partition("", BASE, BASE + DAY - 1, types=("PDF",)).divisible()
          is True, "one day with a type left can still be split")
    check(Partition("", BASE, BASE + DAY).divisible() is True,
          "a range of exactly one day is still divisible by date, because the "
          "floor is >= DAY_MS and not > it  <-- pinned defect")
    raises(lambda: Partition("", 10, 5), "a backwards date range raises")
    raises(lambda: Partition("", -1, 5), "a negative created date raises")
    left, right = bisect(Partition("q", 0, 2 * DAY))
    check(left.lo == 0 and left.hi == DAY,
          "a two day range splits at its midpoint")
    check(right.lo == DAY + 1,
          "the second half starts one millisecond after the first ends, so no "
          "item falls in both  <-- pinned defect")
    exact = bisect(Partition("q", BASE, BASE + DAY))
    check(exact[0].hi == BASE + DAY // 2 and exact[1].lo == BASE + DAY // 2 + 1,
          "and it splits on DATE, rather than falling through to the type "
          "ladder one day early  <-- pinned defect")
    ladder = Partition("q", 0, 10 * DAY, types=("PDF",))
    check(bisect(ladder)[0].types == ("PDF",),
          "a wide range splits on DATE first and spends no type  "
          "<-- pinned defect")
    day = Partition("q", BASE, BASE + DAY - 1, types=("PDF", "CSV"))
    hit, miss = bisect(day)
    check(partition_query(hit).endswith("type:(PDF)"),
          "a day at the cap splits on the first type")
    check(partition_query(miss).endswith("-type:(PDF)"),
          "the other half is NOT the remaining types but everything else, so "
          "an item type missing from the list is still enumerated  "
          "<-- pinned defect")
    check(hit.types == () and miss.types == ("CSV",),
          "the matched half has no type left, the complement keeps the rest")
    last = bisect(miss)[1]
    check(last.types == () and partition_query(last).endswith("-type:(CSV)"),
          "after the last named type the complement terminates instead of "
          "emitting type:(CSV) for ever  <-- pinned defect")
    deep = Partition("q", BASE, BASE + DAY - 1, types=BISECT_TYPES)
    for _step in range(4):
        deep = bisect(deep)[0]
    check(partition_query(deep).count("type:(") == 1,
          "four type splits leave ONE type clause, not four nested ones that "
          "grow the url until search answers 414  <-- pinned defect")
    refusal = refuses_enum(
        lambda: bisect(Partition("q", BASE, BASE + DAY - 1)),
        "a one day partition with nothing left to split on REFUSES  "
        "<-- pinned defect")
    check("would be reported as a ghost" in refusal,
          "and the refusal says what an incomplete enumeration would do to "
          "the ghost list  <-- pinned defect")
    check(reconcile_pages("q", [], 0) == [],
          "a crawl with no pages has nothing to reconcile")
    check(reconcile_pages("q", [40, 40], 40) == [],
          "a steady total matching the rows read reconciles silently")
    moved = reconcile_pages("q", [40, 41], 41)
    check(len(moved) == 1 and "moved from 40 to 41" in moved[0],
          "a total that moves mid-crawl is a warning  <-- pinned defect")
    check(len(reconcile_pages("q", [40, 40], 38)) == 1,
          "a crawl that returned fewer rows than the total warns")
    check(reconcile_pages("q", [SEARCH_CEILING], 10000) == [],
          "a capped total raises no row-count warning, because it is bisected "
          "rather than trusted")
    check(len(reconcile_pages("q", [40, 41], 38)) == 2,
          "a total that moved AND came back short reports both")

    class Catalog(object):
        """A stand-in for /sharing/rest/search, with the server's real limits.

        It caps num, it counts only to the ceiling, and it filters on the
        clauses the bisect emits. A clause it does not understand is an error
        rather than a match-everything, because a fake that quietly ignores a
        filter proves nothing.
        """

        def __init__(self, rows, cap=SEARCH_MAX_NUM, reported=None,
                     moving=None):
            self.rows = list(rows)
            self.cap = cap
            self.reported = reported
            self.moving = list(moving) if moving else None
            self.calls = []
            self._cache = {}

        def select(self, query):
            if query in self._cache:
                return self._cache[query]
            rows = self.rows
            for clause in query.split(" AND "):
                clause = clause.strip()
                if clause.startswith("(") and clause.endswith(")"):
                    continue                  # the base query matches all rows
                found = re.match(r"^created:\[(\d+) TO (\d+)\]$", clause)
                if found:
                    lo, hi = int(found.group(1)), int(found.group(2))
                    rows = [r for r in rows if lo <= r["created"] <= hi]
                    continue
                found = re.match(r"^(-?)type:\((.*)\)$", clause)
                if found:
                    neg, body = found.groups()
                    terms = [t.strip().strip('"') for t in body.split(" OR ")]
                    rows = [r for r in rows
                            if (r.get("type") in terms) != bool(neg)]
                    continue
                raise ValueError("the catalog cannot answer %r" % clause)
            self._cache[query] = rows
            return rows

        def __call__(self, query, start, num):
            self.calls.append((query, start, num))
            rows = self.select(query)
            if self.moving:
                total = self.moving[min(len(self.calls) - 1,
                                        len(self.moving) - 1)]
            elif self.reported is not None:
                total = self.reported
            else:
                total = min(len(rows), SEARCH_CEILING)
            size = min(num, self.cap)         # the silent server-side cap
            page = rows[start - 1:start - 1 + size]
            reach = min(len(rows), SEARCH_CEILING)
            nxt = start + len(page)
            return {"total": total, "start": start, "num": len(page),
                    "nextStart": -1 if (not page or nxt > reach) else nxt,
                    "results": page}

    def rows(count, first=0, kind="Feature Service", spread=DAY):
        return [{"id": "item%06d" % (first + n),
                 "title": "Layer %d" % (first + n),
                 "owner": "jsmith",
                 "type": kind if isinstance(kind, str) else kind[n % len(kind)],
                 "access": "org",
                 "url": "%s/Bulk%d/FeatureServer" % (REST, first + n),
                 "created": BASE + (first + n) * spread}
                for n in range(count)]

    raises(lambda: Catalog([]).select("owner:jsmith"),
           "the stand-in portal refuses a query clause it does not "
           "understand, rather than matching everything  <-- pinned defect")

    small = Catalog(rows(250))
    got, totals, pages = crawl_partition(small, "created:[0 TO %d]" % NOW)
    check(len(got) == 250,
          "paging reads all 250 items, not the 100 the server caps a page at  "
          "<-- pinned defect")
    check(pages == 3 and totals == [250, 250, 250],
          "in three pages, with the total read on every one")
    check(all(call[2] == 100 for call in small.calls),
          "every page asked for exactly 100, the clamped size")
    dribble = Catalog(rows(250), cap=10)
    got, _t, pages = crawl_partition(dribble, "created:[0 TO %d]" % NOW)
    check(len(got) == 250 and pages == 25,
          "a server that quietly returns ten rows for a page of a hundred is "
          "still paged to the end  <-- pinned defect")
    empty = Catalog([])
    got, totals, pages = crawl_partition(empty, "created:[0 TO %d]" % NOW)
    check(got == {} and totals == [0] and pages == 1,
          "an empty result set is one page and no items")
    # Union by id, not append. An item edited between two pages is returned on
    # both of them by a portal that sorts on created and renumbers nothing, and
    # counting it twice inflates the enumeration until it no longer reconciles
    # against the total the server reported.
    repeated = rows(3)

    def doubled(query, start, num):
        page = repeated if start == 1 else (repeated[:1] if start == 4 else [])
        return {"total": 3, "results": page,
                "nextStart": -1 if start > 4 else start + len(page)}
    got, totals, pages = crawl_partition(doubled, "created:[0 TO %d]" % NOW)
    check(len(got) == 3 and pages == 3,
          "an item returned on two pages is collected ONCE, over three pages, "
          "so the crawl still reconciles against the reported total  "
          "<-- pinned defect")
    check(sorted(got) == ["item000000", "item000001", "item000002"],
          "and it is the ids that are unique, not merely the count")
    raises(lambda: crawl_partition(lambda q, s, n: ["not", "a", "page"], "q"),
           "a fetch returning something that is not a search response raises")
    raises(lambda: crawl_partition(
        lambda q, s, n: {"total": 1, "results": ["not an object"]}, "q"),
        "a search result that is not an object raises")
    raises(lambda: crawl_partition(
        lambda q, s, n: {"total": 1, "results": [{"title": "no id"}]}, "q"),
        "a search result with no id raises rather than being keyed under None")

    plain, warnings = enumerate_items(Catalog(rows(250)), base="orgid:ORG",
                                      now_ms=NOW, types=())
    check(len(plain) == 250 and warnings == [],
          "an org under the ceiling enumerates in one partition")
    huge, _w = enumerate_items(Catalog(rows(10400, spread=DAY // 16)),
                               base="orgid:ORG", now_ms=NOW, types=())
    check(len(huge) == 10400,
          "an org of 10,400 items enumerates to 10,400, not to the 10,000 the "
          "server reported  <-- pinned defect")
    by_type = rows(10400, kind=("PDF", "CSV"), spread=0)
    for row in by_type:
        row["created"] = BASE
    typed, _w = enumerate_items(Catalog(by_type), base="orgid:ORG", now_ms=NOW,
                                types=("PDF", "CSV"))
    check(len(typed) == 10400,
          "10,400 items created in the same millisecond are enumerated by "
          "splitting on item type  <-- pinned defect")
    drifted, moved_w = enumerate_items(Catalog(rows(250), moving=[250, 251]),
                                       base="orgid:ORG", now_ms=NOW, types=())
    check(len(drifted) == 250 and len(moved_w) == 2,
          "a portal that changed mid-crawl enumerates what it read and warns "
          "twice")
    liar = refuses_enum(
        lambda: enumerate_items(Catalog(rows(50), reported=SEARCH_CEILING),
                                base="orgid:ORG", now_ms=BASE + 30 * DAY,
                                types=()),
        "a portal that reports the cap however narrow the query REFUSES, "
        "rather than handing back a list that would make every service a "
        "ghost  <-- pinned defect")
    check("cannot be enumerated" in liar,
          "and says the items under it were not enumerated")
    budget = refuses_enum(
        lambda: enumerate_items(Catalog(rows(50), reported=SEARCH_CEILING),
                                base="orgid:ORG", now_ms=NOW, types=(),
                                max_partitions=4),
        "an enumeration that runs past --max-partitions refuses instead of "
        "bisecting for ever  <-- pinned defect")
    check("gave up after 4 partitions" in budget,
          "the budget refusal says how many partitions it visited")
    raises(lambda: enumerate_items(Catalog([]), max_partitions=0),
           "a partition budget of zero raises")
    progress = []
    enumerate_items(Catalog(rows(10400, spread=DAY // 16)), base="orgid:ORG",
                    now_ms=NOW, types=(), echo=progress.append)
    check(any("splitting" in line for line in progress),
          "the progress echo says when a partition is split")
    check(any("item(s) from" in line for line in progress),
          "and how many items each finished partition gave")
    walltime, _w = enumerate_items(Catalog(rows(3)), base="orgid:ORG",
                                   types=())
    check(len(walltime) == 3,
          "an enumeration with no now_ms uses the wall clock and still reads "
          "the org")

    # ---- the server and the portal, answered in process
    #
    # No socket is opened and no credential is real. _opener is swapped for a
    # stand-in that answers the paths a federated deployment answers,
    # including the failures that matter: a 200 carrying an error envelope,
    # which is how ArcGIS reports a dead token, and an exception out of urllib
    # that quotes the failing url back with the token still in it.

    class FakeResponse(object):
        def __init__(self, body, status=200, text=None):
            self.body = body
            self.status = status
            self.text = text

        def read(self):
            if self.text is not None:
                return self.text.encode("utf-8")
            return json.dumps(self.body).encode("utf-8")

    class NoStatus(FakeResponse):
        """A response object that never grew a .status attribute."""

        def __init__(self, body):
            FakeResponse.__init__(self, body)
            del self.status

    class Deployment(object):
        """A portal and a federated server answering in process."""

        def __init__(self, catalog=None, services=None, folders=None,
                     org="ORG123", token="TESTTOKEN", open_error=None,
                     fail_search_after=None, anonymous=(), login_page=(),
                     http_error=(), down=()):
            self.catalog = catalog
            self.services = services if services is not None else []
            self.folders = folders or {}
            self.org = org
            self.token = token
            self.open_error = open_error
            self.fail_search_after = fail_search_after
            self.anonymous = set(anonymous)
            self.login_page = set(login_page)
            self.http_error = dict(http_error)
            self.down = set(down)
            self.searches = 0
            self.targets = []
            self.posted = []
            self.timeouts = []
            self.insecure = None

        def __call__(self, insecure):          # stands in for _opener(insecure)
            self.insecure = insecure
            return self

        def open(self, target, data=None, timeout=None):
            self.timeouts.append(timeout)
            if data is None:
                path, _sep, query = target.partition("?")
            else:
                path, query = target, data.decode("utf-8")
                self.posted.append(query)
            self.targets.append(target)
            if self.open_error is not None:
                raise self.open_error(target)
            params = dict(urllib.parse.parse_qsl(query))
            # A probe url ends in a service type; a catalog url does not.
            # Routing on "/rest/services/" alone sent every folder listing to
            # the probe handler, and the walk came back with one folder.
            tail = path.rstrip("/").rsplit("/", 1)[-1]
            if tail.lower() in _TYPE_BY_LOWER and "/sharing/" not in path:
                return self._service(path, params)
            return FakeResponse(self._body(path, params))

        def _service(self, path, params):
            """One service answering, or refusing, a probe."""
            name = path.split("/rest/services/", 1)[1]
            if name in self.down:
                raise OSError("[Errno 111] Connection refused")
            if name in self.http_error:
                raise urllib.error.HTTPError(path, self.http_error[name],
                                             "no", {}, None)
            if name in self.login_page:
                return FakeResponse(None, 200,
                                    "<html><body>Sign in</body></html>")
            if name in self.anonymous or params.get("token") == self.token:
                return FakeResponse({"currentVersion": 11.2,
                                     "serviceDescription": name})
            return FakeResponse({"error": {"code": 499,
                                           "message": "Token Required"}})

        def _body(self, path, params):
            if path.endswith("/generateToken"):
                if params.get("password") != "hunter2":
                    return {"error": {"code": 400,
                                      "message": "Invalid username or "
                                                 "password."}}
                return {"token": self.token, "expires": 9999999999999}
            if path.endswith("/portals/self"):
                return {"id": self.org} if self.org else {}
            if path.endswith("/search"):
                self.searches += 1
                if (self.fail_search_after is not None
                        and self.searches > self.fail_search_after):
                    return {"error": {"code": 498, "message": "Invalid token."}}
                return self.catalog(params.get("q") or "",
                                    int(params.get("start") or 1),
                                    int(params.get("num") or 10))
            for marker in ("/rest/services", "/admin/services"):
                if marker in path:
                    folder = path.split(marker, 1)[1].strip("/")
                    if folder in self.folders:
                        return self.folders[folder]
                    return {"error": {"code": 404,
                                      "message": "no folder " + folder}}
            return {"error": {"code": 400, "message": "unhandled " + path}}

    def serving(deployment, fn):
        """Run fn with that deployment answering, then put _opener back."""
        saved = globals()["_opener"]
        globals()["_opener"] = deployment
        try:
            return fn()
        finally:
            globals()["_opener"] = saved

    class Console(io.StringIO):
        """A stdout that reports an encoding, the way a real console does."""
        encoding = "utf-8"

    def captured(fn, encoding="utf-8"):
        """Run fn with stdout and stderr collected. Returns (result, text)."""
        console = Console()
        console.encoding = encoding
        saved = (sys.stdout, sys.stderr)
        sys.stdout, sys.stderr = console, console
        try:
            outcome = fn()
        finally:
            sys.stdout, sys.stderr = saved
        return outcome, console.getvalue()

    SITE_FOLDERS = {
        "": {"folders": ["Transport"],
             "services": [{"name": "Roads", "type": "MapServer"},
                          {"name": "Parcels", "type": "FeatureServer"}]},
        "Transport": {"folders": [],
                      "services": [{"name": "Transport/Rail",
                                    "type": "MapServer"}]},
    }
    SITE_ITEMS = [
        {"id": "i1", "title": "Roads", "owner": "jsmith", "type": "Map Service",
         "access": "public", "created": BASE,
         "url": "https://gis/arcgis/rest/services/Roads/MapServer"},
        {"id": "i2", "title": "Parcels", "owner": "ann",
         "type": "Feature Service", "access": "org", "created": BASE + 1,
         "url": SERVER + "/rest/services/Parcels/FeatureServer/0"},
        {"id": "i3", "title": "A web map", "owner": "ann", "type": "Web Map",
         "access": "org", "created": BASE + 2, "url": ""},
        {"id": "i4", "title": "Gone", "owner": "ann", "type": "Map Service",
         "access": "org", "created": BASE + 3,
         "url": REST + "/Deleted/MapServer"},
    ]

    def site(**kw):
        opts = {"catalog": Catalog(SITE_ITEMS), "folders": SITE_FOLDERS,
                "anonymous": ["Transport/Rail/MapServer"]}
        opts.update(kw)
        return Deployment(**opts)

    where = site()
    services = serving(where, lambda: walk_catalog(
        catalog_fetch(SERVER, "TESTTOKEN"), SERVER))
    check(len(services) == 3,
          "the real catalog fetch walks the root and its folder over the "
          "opener")
    check(all("token=TESTTOKEN" in t for t in where.targets),
          "the token is sent with every catalog call")
    check(all("f=json" in t for t in where.targets),
          "every call asks for f=json, or the server answers with an html "
          "page and json.loads gets a doctype  <-- pinned defect")
    check(where.insecure is False,
          "the default opener verifies the certificate  <-- pinned defect")
    check(sorted(s["key"] for s in services)
          == ["gis/parcels/FeatureServer", "gis/roads/MapServer",
              "gis/transport/rail/MapServer"],
          "and the keys come back the way the reconcile wants them")

    anon_site = site()
    keys, reasons = serving(anon_site, lambda: probe_all(
        services, probe=lambda u, i, t: probe_service(u, i, t)))
    check(keys == set(["gis/transport/rail/MapServer"]),
          "the probe finds the one service that answers without a token  "
          "<-- pinned defect")
    check(not any("token=" in t for t in anon_site.targets),
          "and not one probe carried a token  <-- pinned defect")
    check(all("f=json" in t for t in anon_site.targets),
          "every probe asked for f=json")
    check("Token Required" in reasons["gis/roads/MapServer"],
          "the closed services keep the server's own refusal")
    # The probe gets its own, shorter, budget. A catalog read happens once
    # and can afford a minute; a probe happens once per service and a
    # service that is down is the ordinary case, so a catalog-sized budget
    # is an audit that never finishes on a server with hundreds of them.
    check(set(anon_site.timeouts) == set([20]),
          "every probe waited 20 seconds and not a second longer  "
          "<-- pinned defect")
    check(set(where.timeouts) == set([60]),
          "while a catalog read gets the full 60, so the two budgets are "
          "genuinely different numbers  <-- pinned defect")
    # probe_all was given the budget above. This one asks probe_service
    # with no budget at all, which is the signature default, and it has to
    # be the probe budget rather than the catalog one.
    bare = site()
    serving(bare, lambda: probe_service(REST + "/Transport/Rail/MapServer"))
    check(bare.timeouts == [20],
          "a probe called with no budget still waits 20 seconds, not the 60 "
          "a catalog read gets  <-- pinned defect")

    html_site = site(anonymous=(), login_page=["Roads/MapServer"],
                     http_error={"Parcels/FeatureServer": 403})
    keys, reasons = serving(html_site, lambda: probe_all(services))
    check(keys == set(),
          "a service that answers a probe with a login page is NOT reported "
          "anonymous  <-- pinned defect")
    check("login page" in reasons["gis/roads/MapServer"],
          "and the reason says what came back")
    check(reasons["gis/parcels/FeatureServer"] == "HTTP 403",
          "a service that refuses with HTTP 403 is reported as refusing")
    refused = site(open_error=lambda t: OSError(
        "[Errno 111] Connection refused"))
    down = serving(refused, lambda: probe_service(REST + "/Roads/MapServer"))
    check(down == (0, None, "[Errno 111] Connection refused"),
          "a probe with nothing listening comes back as a transport error, "
          "not a traceback  <-- pinned defect")
    check(is_anonymous(*down)[0] is False,
          "and a service that is down is not reported anonymous")

    nostatus = Deployment()
    nostatus.open = lambda target, data=None, timeout=None: NoStatus(live)
    check(serving(nostatus, lambda: probe_service(
        REST + "/Roads/MapServer"))[0] == 200,
        "a response object with no .status is read as 200 rather than "
        "raising  <-- pinned defect")

    counted = serving(site(), lambda: enumerate_items(
        portal_fetch(PORTAL, "TESTTOKEN"), base="orgid:ORG123", now_ms=NOW,
        types=()))[0]
    check(len(counted) == 4,
          "the real portal fetch enumerates the org over the opener")
    search_site = site()
    serving(search_site, lambda: enumerate_items(
        portal_fetch(PORTAL, "TESTTOKEN"), base="orgid:ORG123", now_ms=NOW,
        types=()))
    check(any("sortField=created" in t for t in search_site.targets),
          "results are sorted by created, the field the bisect partitions on  "
          "<-- pinned defect")
    anonymous_read = site()
    serving(anonymous_read, lambda: enumerate_items(
        portal_fetch(PORTAL, None), base="orgid:ORG123", now_ms=NOW, types=()))
    check(not any("token=" in t for t in anonymous_read.targets),
          "an anonymous portal read sends no token parameter at all")
    check(serving(site(), lambda: org_id(PORTAL, "TESTTOKEN")) == "ORG123",
          "the org id is read from portals/self")
    check(serving(site(org=None), lambda: org_id(PORTAL, None)) is None,
          "a portal that will not name its org gives no id, not a wrong one")

    admin_site = site()
    serving(admin_site, lambda: walk_catalog(
        catalog_fetch(SERVER, "TESTTOKEN", admin=True), SERVER))
    check(all("/admin/services" in t for t in admin_site.targets),
          "--admin reads the admin catalog rather than the rest one")
    check(all("/rest/services" not in t for t in admin_site.targets),
          "and asks the rest catalog for nothing")

    unhandled = fails(
        lambda: serving(site(), lambda: portal_call(PORTAL, "content/users/x",
                                                    {})),
        "the stand-in deployment refuses a path it does not implement, so a "
        "call this tool should not be making cannot pass  <-- pinned defect")
    check("unhandled" in unhandled, "and says which path it would not answer")

    class NotAnObject(Deployment):
        def _body(self, path, params):
            return ["maintenance", "in progress"]

    shaped = fails(lambda: serving(NotAnObject(),
                                   lambda: org_id(PORTAL, None)),
                   "a portal answering with a JSON array is refused, not fed "
                   "to body.get() as a traceback  <-- pinned defect")
    check("not an object" in shaped and "list" in shaped,
          "and the refusal says what came back instead")
    fails(lambda: serving(NotAnObject(), lambda: walk_catalog(
        catalog_fetch(SERVER, "T"), SERVER)),
        "the same guard covers the server catalog, because it is one guard "
        "and not one per caller")

    check(_error_text({"error": {"code": 499, "message": "Token Required"}})
          == "499 Token Required",
          "the portal and services directory error shape is read")
    check(_error_text({"error": "Service unavailable"})
          == "Service unavailable",
          "and so is a bare string under error, which a proxy sends")
    check(_error_text({"status": "error", "code": 500,
                       "messages": ["bad one", "worse one"]})
          == "500 bad one; worse one",
          "and so is the Administrator API shape")
    check(_error_text({"status": "ok", "services": []}) == "",
          "an answer that says nothing went wrong gives no message")

    check(serving(site(), lambda: generate_token(PORTAL, "gis_admin",
                                                 "hunter2")) == "TESTTOKEN",
          "a username and password are exchanged for a token")
    signed = site()
    serving(signed, lambda: generate_token(PORTAL, "gis_admin", "hunter2"))
    check(any("password=hunter2" in body for body in signed.posted),
          "the password goes in the POST body, which is where it belongs")
    check(not any("password" in t for t in signed.targets),
          "the password never appears in a url  <-- pinned defect")
    refused_login = fails(lambda: serving(site(), lambda: generate_token(
        PORTAL, "gis_admin", "wrongpass")),
        "a rejected sign-in is raised, not returned as a token")
    check("Invalid username or password" in refused_login,
          "the portal's own reason survives into the error")
    check("wrongpass" not in refused_login,
          "the rejected password is not quoted back in the error  "
          "<-- pinned defect")
    fails(lambda: serving(site(token=None), lambda: generate_token(
        PORTAL, "gis_admin", "hunter2")),
        "a sign-in that returns no token raises rather than returning None")

    leaky = site(open_error=lambda target: ValueError(
        "unknown url type: %r" % target))
    quoted = fails(lambda: serving(leaky, lambda: org_id(PORTAL, "TESTTOKEN")),
                   "an exception out of urllib is raised as a portal error")
    check("TESTTOKEN" not in quoted,
          "the token in the url urllib quoted back is redacted out of the "
          "error  <-- pinned defect")
    check(REDACTED in quoted, "and the redaction is visible in its place")
    gateway = site(open_error=lambda target: urllib.error.HTTPError(
        target, 500, "Internal Server Error", {}, None))
    check("500" in fails(lambda: serving(gateway, lambda: generate_token(
        PORTAL, "gis_admin", "hunter2")),
        "an HTTP error from a gateway is raised as an error"),
        "and the status code survives into the message")
    hidden = fails(lambda: serving(
        site(open_error=lambda t: ValueError("boom %s" % t)),
        lambda: generate_token(PORTAL, "gis_admin", "hunter2")),
        "a POST that blows up inside urllib is raised")
    check("hunter2" not in hidden,
          "and the password it carried is not in the message  "
          "<-- pinned defect")
    refered = site()
    serving(refered, lambda: generate_token(
        "https://svc:PORTPW@gis.example.org/portal?token=PORTTOK", "gis_admin",
        "hunter2"))
    check(refered.posted and not any("PORTPW" in b or "PORTTOK" in b
                                     for b in refered.posted)
          and "referer=https%3A%2F%2Fgis.example.org%2Fportal" in
          refered.posted[0],
          "the referer posted to the portal carries no password and no token "
          "from the --portal url  <-- pinned defect")
    dead = fails(lambda: serving(site(fail_search_after=0), lambda:
                                 enumerate_items(
                                     portal_fetch(PORTAL, "TESTTOKEN"),
                                     base="orgid:ORG123", now_ms=NOW,
                                     types=())),
                 "a token the portal rejects fails the enumeration")
    check("498" in dead and "TESTTOKEN" not in dead,
          "the portal's error code is reported and the dead token is not  "
          "<-- pinned defect")

    insecure_site = site()
    serving(insecure_site, lambda: org_id(PORTAL, None, insecure=True))
    check(insecure_site.insecure is True,
          "--insecure reaches the opener when it is asked for")
    # The real _opener, asked what it actually does to TLS. isinstance()
    # answers OpenerDirector for both branches, so a check on the type would
    # pass just as well if --insecure were the default. The handler is read.
    def tls_modes(opener):
        """(verify_mode, check_hostname) of every https handler on an opener.

        urllib leaves the context None on some versions, and a context it
        builds later verifies, so None is read here as the verifying default.
        """
        return [(ssl.CERT_REQUIRED, True)
                if getattr(h, "_context", None) is None
                else (h._context.verify_mode, h._context.check_hostname)
                for h in opener.handlers
                if isinstance(h, urllib.request.HTTPSHandler)]

    plain_modes = tls_modes(_opener(False))
    check(plain_modes and all(mode == (ssl.CERT_REQUIRED, True)
                              for mode in plain_modes),
          "the real opener VERIFIES the certificate and the hostname unless "
          "it was asked not to  <-- pinned defect")
    check(tls_modes(_opener(True)) == [(ssl.CERT_NONE, False)],
          "and --insecure really reaches ssl with BOTH checks off, rather "
          "than building the same verifying opener twice  <-- pinned defect")

    os.environ[SECRET_ENV] = "from-the-environment"
    try:
        check(read_secret("gis_admin") == "from-the-environment",
              "the password is read from %s when it is set" % SECRET_ENV)
    finally:
        del os.environ[SECRET_ENV]
    asked = []
    real_getpass = getpass.getpass
    getpass.getpass = lambda prompt: asked.append(prompt) or "typed-in"
    try:
        check(read_secret("gis_admin") == "typed-in",
              "with no environment variable the password is prompted for")
    finally:
        getpass.getpass = real_getpass
    check(len(asked) == 1 and "not echoed" in asked[0],
          "the prompt says the password will not be echoed  <-- pinned defect")
    check("gis_admin" in asked[0], "and names the user it is signing in as")

    # ---- the command line, end to end
    workdir = tempfile.mkdtemp(prefix="ghostsvc-selftest-")
    try:
        out_json = os.path.join(workdir, "ghosts.json")
        out_csv = os.path.join(workdir, "nested", "ghosts.csv")
        ARGV = ["--server", SERVER, "--portal", PORTAL, "--token", "TESTTOKEN"]
        os.environ.pop(TOKEN_ENV, None)
        RAIL_ITEM = {"id": "i5", "title": "Rail", "owner": "ann",
                     "type": "Map Service", "access": "org",
                     "created": BASE + 4, "url": REST + "/Transport/Rail/"
                                                        "MapServer"}

        code, seen = captured(lambda: serving(site(), lambda: main(ARGV)))
        check(code == 1, "a run with findings exits 1")
        check("3 service(s) on the server" in seen,
              "and prints what it compared")
        check("anonymous-ghost" in seen,
              "the anonymously reachable service with no item is reported  "
              "<-- pinned defect")
        check("orphan" in seen, "and so is the item whose service is gone")
        check("TESTTOKEN" not in seen,
              "the token never reaches stdout  <-- pinned defect")
        check("1 portal item(s) carried no url" in seen,
              "the web map is reported as unreconciled rather than as an "
              "orphan  <-- pinned defect")

        code, seen = captured(lambda: serving(
            site(anonymous=(), catalog=Catalog(SITE_ITEMS[:3] + [
                {"id": "i5", "title": "Rail", "owner": "ann",
                 "type": "Map Service", "access": "org", "created": BASE + 4,
                 "url": REST + "/Transport/Rail/MapServer"}])),
            lambda: main(ARGV)))
        check(code == 0 and "Every service on the server has a portal item"
              in seen,
              "a deployment where every service has an item and none answers "
              "anonymously exits 0")
        code, seen = captured(lambda: serving(
            site(anonymous=(), down=["Roads/MapServer"],
                 catalog=Catalog(SITE_ITEMS[:3] + [RAIL_ITEM])),
            lambda: main(ARGV)))
        check(code == 2 and "1 of 3 service(s) could not be probed" in seen,
              "one service down for the probe and no finding exits 2, not 0  "
              "<-- pinned defect")

        every = [r + "/MapServer" for r in ("Roads", "Transport/Rail")]
        every.append("Parcels/FeatureServer")
        code, seen = captured(lambda: serving(
            site(anonymous=(), down=every,
                 catalog=Catalog(SITE_ITEMS[:3] + [RAIL_ITEM])),
            lambda: main(ARGV)))
        check(code == 2 and "no probe got an answer" in seen
              and "not one of them answered" not in seen,
              "a server whose every service is down for the probe exits 2 and "
              "does not claim that none answered anonymously  "
              "<-- pinned defect")
        code, seen = captured(lambda: serving(
            site(catalog=Catalog(SITE_ITEMS[:3] + [RAIL_ITEM])),
            lambda: main(ARGV + ["--no-probe"])))
        check(code == 0 and "probe was not run" in seen
              and "not one of them answered" not in seen,
              "--no-probe with nothing to report does not claim that none "
              "answered anonymously  <-- pinned defect")
        np_csv = os.path.join(workdir, "noprobe.csv")
        captured(lambda: serving(site(), lambda: main(
            ARGV + ["--no-probe", "--out", np_csv, "--format", "csv",
                    "--apply"])))
        with io.open(np_csv, "r", encoding="utf-8", newline="") as handle:
            np_rows = list(csv.reader(handle))[1:]
        check(dict((row[0], row[7]) for row in np_rows)
              == {"ghost": "", "orphan": ""},
              "with --no-probe the anonymous column of a ghost and of an "
              "orphan is empty, not no  <-- pinned defect")
        or_csv = os.path.join(workdir, "orphan.csv")
        or_json = os.path.join(workdir, "orphan.json")
        for target, fmt in ((or_csv, "csv"), (or_json, "json")):
            captured(lambda: serving(site(), lambda: main(
                ARGV + ["--out", target, "--format", fmt, "--apply"])))
        with io.open(or_csv, "r", encoding="utf-8", newline="") as handle:
            or_rows = list(csv.reader(handle))[1:]
        with io.open(or_json, "r", encoding="utf-8") as handle:
            or_doc = json.load(handle)
        check(dict((row[0], row[7]) for row in or_rows).get("orphan") == ""
              and [f["anonymous"] for f in or_doc["findings"]
                   if f["kind"] == "orphan"] == [None],
              "a probed run still records an orphan as unknown, because an "
              "orphan's url was never asked  <-- pinned defect")

        code, seen = captured(lambda: serving(site(), lambda: main(
            ARGV + ["--out", workdir, "--format", "csv", "--apply"])))
        check(code == 2 and "could not write" in seen,
              "a report that cannot be written exits 2 with a message, not 1 "
              "with a traceback  <-- pinned defect")

        code, seen = captured(lambda: serving(site(), lambda: main([
            "--server", "https://svcuser:SVCPW@gis.example.org/arcgis",
            "--portal", PORTAL + "?token=PORSECRET", "--token", "TESTTOKEN"])))
        check(code == 1 and "SVCPW" not in seen and "PORSECRET" not in seen,
              "a password in --server and a token in --portal are not echoed  "
              "<-- pinned defect")
        leak_csv = os.path.join(workdir, "leak.csv")
        code, seen = captured(lambda: serving(
            site(catalog=Catalog(SITE_ITEMS[:3] + [{
                "id": "i6", "title": "Old", "owner": "ann",
                "type": "Map Service", "access": "org", "created": BASE + 5,
                "url": "https://itemuser:ITEMPW@gis.example.org/arcgis/rest/"
                       "services/Old/MapServer"}])),
            lambda: main(ARGV + ["--out", leak_csv, "--format", "csv",
                                 "--apply"])))
        with io.open(leak_csv, "r", encoding="utf-8", newline="") as handle:
            leak_text = handle.read()
        check("ITEMPW" not in seen and "ITEMPW" not in leak_text
              and "Old/MapServer" in leak_text,
              "a password inside a portal item's url reaches neither the "
              "terminal nor the csv, and the orphan is still reported  "
              "<-- pinned defect")

        os.environ[TOKEN_ENV] = "ENVTOKEN"
        try:
            env_site = site(token="ENVTOKEN")
            code, seen = captured(lambda: serving(env_site, lambda: main(
                ["--server", SERVER, "--portal", PORTAL])))
            flag_site = site()
            captured(lambda: serving(flag_site, lambda: main(ARGV)))
        finally:
            del os.environ[TOKEN_ENV]
        check(code == 1 and any("token=ENVTOKEN" in t
                                for t in env_site.targets),
              "a token in GHOSTSVC_TOKEN is used when --token is absent")
        check("ENVTOKEN" not in seen, "and is never printed")
        check(any("token=TESTTOKEN" in t for t in flag_site.targets)
              and not any("ENVTOKEN" in t for t in flag_site.targets),
              "--token wins over the environment")

        code, seen = captured(lambda: serving(site(), lambda: main(
            ARGV + ["--no-probe"])))
        check(code == 1 and "anonymous-ghost" not in seen
              and "probing" not in seen,
              "--no-probe reports the ghost without asking any service "
              "anything")
        quiet = site()
        captured(lambda: serving(quiet, lambda: main(ARGV + ["--no-probe"])))
        check(not any("/rest/services/Transport/Rail/MapServer?" in t
                      for t in quiet.targets),
              "and really opens no service url  <-- pinned defect")

        code, seen = captured(lambda: serving(site(), lambda: main(
            ARGV + ["--out", out_json])))
        check(code == 1 and "Check only" in seen,
              "an --out without --apply says it wrote nothing")
        check(not os.path.exists(out_json),
              "and the file really is not there  <-- pinned defect")

        code, seen = captured(lambda: serving(site(), lambda: main(
            ARGV + ["--out", out_json, "--apply"])))
        check(code == 1 and os.path.exists(out_json),
              "--apply writes the report")
        with io.open(out_json, "r", encoding="utf-8") as handle:
            written = json.load(handle)
        check(written["services"] == 3 and written["items"] == 4,
              "the written report holds what was compared")
        check(written["ghosts"] == 1 and written["orphans"] == 1
              and written["anonymous"] == 1,
              "and the counts of each finding")
        check(len(written["unreadable_items"]) == 1,
              "and the item that could not be reconciled")
        with io.open(out_json, "r", encoding="utf-8") as handle:
            raw_text = handle.read()
        check("TESTTOKEN" not in raw_text,
              "no credential reaches the report file on disk  "
              "<-- pinned defect")
        check("hunter2" not in raw_text, "and no password either")

        code, seen = captured(lambda: serving(site(), lambda: main(
            ARGV + ["--out", out_csv, "--format", "csv", "--apply"])))
        check(code == 1 and os.path.exists(out_csv),
              "--format csv writes a csv, creating the directory it needs")
        with io.open(out_csv, "r", encoding="utf-8", newline="") as handle:
            table = list(csv.reader(handle))
        check(table[0] == list(CSV_FIELDS),
              "the csv leads with the fixed column header")
        check(len(table) == 3,
              "and holds one row per finding under it, the ghost and the "
              "orphan")
        check(all(len(row) == len(CSV_FIELDS) for row in table),
              "every csv row has every column")
        with io.open(out_csv, "r", encoding="utf-8", newline="") as handle:
            csv_text = handle.read()
        check("\n\n" not in csv_text.replace("\r\n", "\n"),
              "the csv has no blank line between rows, which is what "
              "newline='' prevents on windows  <-- pinned defect")
        check("TESTTOKEN" not in csv_text, "and carries no token")

        code, seen = captured(lambda: serving(
            site(catalog=Catalog(SITE_ITEMS, reported=SEARCH_CEILING)),
            lambda: main(ARGV + ["--max-partitions", "4", "--out", out_json,
                                 "--apply"])))
        check(code == 2,
              "an enumeration that could not be completed exits 2 and reports "
              "no ghosts at all  <-- pinned defect")
        check("no ghost list is given" in seen and "[ 50]" not in seen,
              "the refusal explains itself instead of listing services")
        check(written["services"] == 3,
              "and the report from the previous run was not overwritten by a "
              "refused one  <-- pinned defect")

        os.environ[SECRET_ENV] = "hunter2"
        try:
            sign_in = site()
            code, seen = captured(lambda: serving(sign_in, lambda: main(
                ARGV[:4] + ["--username", "gis_admin"])))
        finally:
            del os.environ[SECRET_ENV]
        check(code == 1, "--username signs in and runs the reconcile")
        check(any("password=hunter2" in body for body in sign_in.posted),
              "the password from the environment reached generateToken")
        check("hunter2" not in seen,
              "and never reached stdout  <-- pinned defect")

        os.environ[SECRET_ENV] = "wrongpass"
        try:
            code, seen = captured(lambda: serving(site(), lambda: main(
                ARGV[:4] + ["--username", "gis_admin"])))
        finally:
            del os.environ[SECRET_ENV]
        check(code == 2, "a rejected sign-in exits 2")
        check("wrongpass" not in seen,
              "and the rejected password is not printed  <-- pinned defect")

        code, seen = captured(lambda: serving(site(org=None),
                                              lambda: main(ARGV)))
        check(code == 2 and "pass --query" in seen,
              "a portal that will not name its org asks for --query rather "
              "than reconciling against the wrong item list  "
              "<-- pinned defect")

        public = site()
        code, seen = captured(lambda: serving(public, lambda: main(
            ["--server", SERVER, "--portal", PORTAL])))
        check(code == 1 and "3 service(s) on the server" in seen,
              "a run with no credential at all reconciles what an anonymous "
              "visitor can see")
        check(not any("token=" in target for target in public.targets),
              "and sends no token on any call, to the portal or to a service  "
              "<-- pinned defect")

        wide = site()
        code, seen = captured(lambda: serving(wide, lambda: main(
            ARGV + ["--num", "1000"])))
        check(code == 1 and "4 portal item(s)" in seen,
              "--num 1000 still reads every item, because it is clamped to "
              "the 100 the portal honours  <-- pinned defect")
        check(all("num=100" in t for t in wide.targets if "/search?" in t),
              "and every page really asked for 100 on the wire")

        code, seen = captured(lambda: serving(site(), lambda: main(
            ARGV + ["--query", "type:\"Map Service\""])))
        check(code == 1 and "type:" in seen,
              "--query replaces the org query and is reported back")

        code, seen = captured(lambda: serving(
            site(open_error=lambda t: ValueError("unknown url type: %r" % t)),
            lambda: main(ARGV)))
        check(code == 2 and "TESTTOKEN" not in seen,
              "a call that blows up exits 2 without printing the token")

        code, seen = captured(lambda: serving(site(folders={}),
                                              lambda: main(ARGV)))
        check(code == 2 and "404" in seen,
              "a server whose catalog will not answer exits 2 rather than "
              "reporting every item as an orphan  <-- pinned defect")

        code, seen = captured(lambda: serving(
            site(catalog=Catalog(SITE_ITEMS, cap=1, moving=[4, 5])),
            lambda: main(ARGV)))
        check(code == 1 and "ENUMERATION WARNINGS" in seen,
              "a portal that changed mid-crawl still reports, with a warning "
              "over the ghost list")

        bad_csv = os.path.join(workdir, "surrogate.csv")
        with io.open(bad_csv, "w", encoding="utf-8") as handle:
            handle.write(u"previous report")
        lone = {"id": "i7", "title": "Lone " + chr(0xd800), "owner": "ann",
                "type": "Map Service", "access": "org", "created": BASE + 6,
                "url": REST + "/Gone/MapServer"}
        code, seen = captured(lambda: serving(
            site(catalog=Catalog(SITE_ITEMS[:3] + [lone])), lambda: main(
                ARGV + ["--out", bad_csv, "--format", "csv", "--apply"])))
        with io.open(bad_csv, "r", encoding="utf-8") as handle:
            left = handle.read()
        check(code == 2 and "unexpected UnicodeEncodeError" in seen,
              "a title the csv cannot encode exits 2 with one line, not 1 "
              "with a traceback  <-- pinned defect")
        check("previous report" not in left,
              "and the earlier file is truncated, which the README states")

        pub_rail = {"id": "i5", "title": "Rail", "owner": "ann",
                    "type": "Map Service", "access": "org", "created": BASE + 4,
                    "url": "https://maps.example.net/arcgis/rest/services/"
                           "Transport/Rail/MapServer"}
        alias_catalog = Catalog(SITE_ITEMS[:3] + [pub_rail])
        code, seen = captured(lambda: serving(
            site(anonymous=(), catalog=alias_catalog), lambda: main(ARGV)))
        check(code == 1 and "orphan" in seen,
              "an item registered under another host name is an orphan and "
              "its service a ghost until --host-alias says otherwise")
        code, seen = captured(lambda: serving(
            site(anonymous=(), catalog=alias_catalog), lambda: main(
                ARGV + ["--host-alias", "maps.example.net=gis.example.org"])))
        check(code == 0 and "Every service on the server has a portal item"
              in seen,
              "--host-alias maps.example.net=gis.example.org matches it, end "
              "to end, and the run exits 0")
        code, seen = captured(lambda: main(
            ARGV + ["--host-alias", "maps.example.net"]))
        check(code == 64 and "--host-alias" in seen,
              "a --host-alias that is not a pair is a usage error")

        os.environ.pop(SECRET_ENV, None)
        real_getpass = getpass.getpass

        def no_terminal(prompt):
            raise EOFError()

        getpass.getpass = no_terminal
        try:
            code, seen = captured(lambda: serving(site(), lambda: main(
                ARGV[:4] + ["--username", "gis_admin"])))
        finally:
            getpass.getpass = real_getpass
        check(code == 2 and "no password for gis_admin" in seen
              and "Traceback" not in seen,
              "a --username run with no password and no terminal exits 2 "
              "with a message, not 1 with a traceback  <-- pinned defect")

        real_reconcile = reconcile

        def broken_reconcile(*args, **kwargs):
            raise KeyError("TESTTOKEN")

        globals()["reconcile"] = broken_reconcile
        try:
            code, seen = captured(lambda: serving(site(), lambda: main(ARGV)))
        finally:
            globals()["reconcile"] = real_reconcile
        check(code == 2 and "unexpected KeyError" in seen
              and "TESTTOKEN" not in seen,
              "an exception nothing foresaw exits 2, not 1 which means "
              "findings, and prints its type but not its message, which can "
              "carry a url with a token  <-- pinned defect")

        # the usage errors that never reach a network
        code, seen = captured(lambda: main([]))
        check(code == 64 and "--server is required" in seen,
              "no --server at all is a usage error")
        code, seen = captured(lambda: main(["--server", SERVER]))
        check(code == 64 and "--portal is required" in seen,
              "a --server with no --portal is a usage error, because every "
              "service would be a ghost  <-- pinned defect")
        code, seen = captured(lambda: main(
            ["--server", "gis.example.org/arcgis", "--portal", PORTAL]))
        check(code == 64 and "https://" in seen,
              "a scheme-less --server is refused before any request is built  "
              "<-- pinned defect")
        code, seen = captured(lambda: main(
            ["--server", SERVER, "--portal", "portal.example.org"]))
        check(code == 64 and "https://" in seen,
              "and so is a scheme-less --portal")
        code, seen = captured(lambda: main(ARGV + ["--apply"]))
        check(code == 64 and "--apply needs --out" in seen,
              "--apply with nowhere to write is a usage error")
        code, seen = captured(lambda: main(
            ARGV[:4] + ["--username", "gis_admin", "--insecure"]))
        check(code == 64 and "unverified connection" in seen,
              "--insecure with --username is refused, because that posts the "
              "password down an unverified connection  <-- pinned defect")
        code, seen = captured(lambda: main(ARGV + ["--num", "0"]))
        check(code == 64 and "--num" in seen, "a --num of zero is a usage error")
        code, seen = captured(lambda: main(ARGV + ["--max-partitions", "0"]))
        check(code == 64 and "--max-partitions" in seen,
              "a --max-partitions of zero is a usage error")
        code, seen = captured(lambda: main(ARGV + ["--max-folders", "0"]))
        check(code == 64 and "--max-folders" in seen,
              "a --max-folders of zero is a usage error")
        code, seen = captured(lambda: main(ARGV + ["--timeout", "0"]))
        check(code == 64 and "--timeout" in seen,
              "a --timeout of zero is a usage error")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    # ---- argument handling
    args = _parse(["--server", SERVER, "--portal", PORTAL])
    check(args.apply is False, "--apply defaults to OFF")
    check(args.insecure is False, "--insecure defaults to OFF")
    check(args.admin is False, "--admin defaults to OFF")
    check(args.no_probe is False,
          "--no-probe defaults to OFF, so the anonymity probe runs")
    check(args.self_test is False, "--self-test defaults to OFF")
    check(args.token is None and args.username is None,
          "no credential is assumed")
    check(args.out is None, "nothing is written by default")
    check(args.format == "json", "the default format is json")
    # Pinned to the literal numbers, not to the constants that define them.
    # A check that compares a default against its own constant passes
    # whatever that constant is changed to, and these four are quoted in the
    # README and in --help, so a silent change to one is a documentation bug.
    check(args.num == 100,
          "--num defaults to 100, which is all one search page will give")
    check(args.timeout == 20,
          "--timeout defaults to 20 seconds, short because a probe of a "
          "service that is down is the ordinary case")
    check(args.max_partitions == 4096,
          "--max-partitions defaults to 4096")
    check(args.max_folders == 512, "--max-folders defaults to 512")
    check(_parse(["--self-test"]).self_test is True, "--self-test parses")
    check(_parse(["--server", SERVER, "--apply"]).apply is True,
          "--apply is read")
    def usage_exit(argv):
        noise, sys.stderr = sys.stderr, io.StringIO()
        try:
            _parse(argv)
        except SystemExit as exc:
            return exc.code
        finally:
            sys.stderr = noise
        return None
    check(usage_exit(["--server", SERVER, "--unpublish"]) == 64,
          "an unknown flag is a usage error, exit 64, not argparse's 2  "
          "<-- pinned defect")
    check(usage_exit(["--format", "xml"]) == 64
          and usage_exit(["--num", "x"]) == 64,
          "so are a bad --format and a non-numeric --num")
    check(usage_exit(["--server", SERVER]) is None,
          "and a good command line is not an exit at all")
    refuses(["--server", SERVER, "--ap"],
            "a unique prefix of the write flag is refused, because argparse "
            "would otherwise take --ap for --apply  <-- pinned defect")
    check(_parse(["--server", SERVER, "--insecure"]).insecure is True,
          "--insecure is read")
    check(_parse(["--server", SERVER, "--admin"]).admin is True,
          "--admin is read")
    check(_parse(["--server", SERVER, "--no-probe"]).no_probe is True,
          "--no-probe is read")
    check(_parse(["--server", SERVER, "--portal", PORTAL]).portal == PORTAL,
          "--portal is read")
    check(_parse(["--server", SERVER, "--token", "T"]).token == "T",
          "--token is read")
    check(_parse(["--server", SERVER, "--username", "u"]).username == "u",
          "--username is read")
    check(_parse(["--server", SERVER, "--query", "q"]).query == "q",
          "--query is read")
    check(_parse(["--server", SERVER, "--out", "f.json"]).out == "f.json",
          "--out is read")
    check(_parse(["--server", SERVER, "--format", "csv"]).format == "csv",
          "--format is read")
    check(_parse(["--server", SERVER, "--num", "25"]).num == 25, "--num is read")
    check(_parse(["--server", SERVER, "--timeout", "5"]).timeout == 5,
          "--timeout is read")
    check(_parse(["--server", SERVER, "--max-partitions", "9"]).max_partitions
          == 9, "--max-partitions is read")
    check(_parse(["--server", SERVER, "--max-folders", "9"]).max_folders == 9,
          "--max-folders is read")
    refuses(["--server", SERVER, "--format", "xlsx"],
            "a format nothing can write is refused by argparse")
    refuses(["--server", SERVER, "--num", "lots"],
            "a non-numeric --num is refused")
    refuses(["--server"], "a --server with no value is refused")
    check("password" not in _parse(["--server", SERVER]).__dict__,
          "there is no --password attribute at all, because argv is readable "
          "by every process on the box  <-- pinned defect")
    refuses(["--server", SERVER, "--password", "hunter2"],
            "a --password flag is refused, it does not exist")
    refuses(["--server", SERVER, "--unpublish"],
            "a plausible-looking --unpublish is refused, because this tool "
            "changes nothing  <-- pinned defect")
    refuses(["--server", SERVER, "--delete-ghosts"],
            "and so is --delete-ghosts")

    # ---- the harness itself, which has to be able to report red
    #
    # A self-test whose failure path is never exercised is not a control: it
    # reports green because nothing ever calls the other branch. The harness is
    # run here against thirteen deliberate failures, output swallowed and
    # its tally put back, so that a green run has still proven it can go red.
    def probe_harness():
        check(False, "a false check must be recorded as a failure")
        raises(lambda: None, "a function that raises nothing must fail")
        raises(lambda: 1 / 0, "a function that raises the wrong thing must fail")
        refuses(["--self-test"], "an argv argparse accepts must fail")
        refuses_enum(lambda: None, "an enumeration that returns must fail")
        refuses_enum(lambda: 1 / 0,
                     "an enumeration that raises the wrong thing must fail")
        same(REST + "/A/MapServer", REST + "/B/MapServer",
             "two different services must not compare equal")
        same(REST + "/A/MapServer", "nonsense",
             "a url the normaliser refuses must fail the comparison")
        differ(REST + "/A/MapServer", REST + "/a/mapserver",
               "one service under two spellings must not compare different")
        differ("nonsense", REST + "/A/MapServer",
               "a refused url must fail the difference too")
        return [fails(lambda: None, "a call that does not raise must fail"),
                fails(lambda: 1 / 0,
                      "a call that raises the wrong thing must fail"),
                fails(lambda: bisect(Partition("q", 0, 0)),
                      "a call that refuses the enumeration instead of failing "
                      "must fail")]

    kept_passed, kept_failed = passed[0], list(failed)
    returned, noise = captured(probe_harness)
    probe_passed, probe_failed = passed[0], list(failed)
    passed[0], failed[:] = kept_passed, kept_failed
    check(len(probe_failed) - len(kept_failed) == 13,
          "the harness records a false check, a missing exception, two wrong "
          "exceptions, an argv argparse accepted, two bad enumerations, four "
          "bad url comparisons and three bad calls as thirteen failures, so a "
          "broken tool turns this self-test red  <-- pinned defect")
    check(probe_passed == kept_passed,
          "not one of those thirteen was counted as a pass")
    check(noise.count("FAIL  ") == 13,
          "every recorded failure prints a FAIL line the operator can see")
    check(returned == ["", "", ""],
          "a call that did not fail the right way yields no message to assert "
          "on")

    red_lines, red_code = verdict(7, ["one", "two"])
    check(red_code == 1 and red_lines == ["7 assertions, 2 failed",
                                          "  FAILED: one", "  FAILED: two"],
          "a failed run prints its count and every failed label, and exits 1")
    green_lines, green_code = verdict(7, [])
    check(green_code == 0 and green_lines == ["7 assertions, 0 failed"],
          "a clean run prints the footer the README quotes, and exits 0")
    import runpy
    namespace = runpy.run_path(os.path.abspath(__file__),
                               run_name="ghostsvc_imported")
    check(callable(namespace["main"]),
          "importing the file runs nothing, because main() sits behind the "
          "__main__ guard")

    print("-" * 68)
    lines, code = verdict(passed[0] + len(failed), failed)
    for line in lines:
        print(line)
    return code


# ----------------------------------------------------------------------- cli

class _Parser(argparse.ArgumentParser):
    """An ArgumentParser whose usage errors exit 64, as the README promises.

    argparse exits 2, and 2 is this tool's code for "the server or the portal
    could not be read", so a typo in a scheduled job would read as an outage.
    """

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(64, "%s: error: %s\n" % (self.prog, message))


def _parse(argv):
    ap = _Parser(
        prog="ghostsvc.py",
        description="Reconcile portal items against federated server "
                    "services, and name the anonymously accessible services "
                    "that appear in no sharing report.",
        epilog="Read-only. No flag changes anything on the server or in the "
               "portal. The password is never a flag: export %s or answer the "
               "prompt. A token is better exported as %s than passed with "
               "--token." % (SECRET_ENV, TOKEN_ENV),
        allow_abbrev=False,
    )
    ap.add_argument("--server",
                    help="federated server url, e.g. "
                         "https://gis.example.com/arcgis")
    ap.add_argument("--portal",
                    help="portal url, e.g. https://portal.example.com/portal")
    ap.add_argument("--query",
                    help="search query for the item side (default: orgid of "
                         "the signed-in org)")
    ap.add_argument("--token",
                    help="an existing portal token. Visible in the process "
                         "list and in shell history: export %s instead."
                         % TOKEN_ENV)
    ap.add_argument("--username",
                    help="generate a token for this user. The password comes "
                         "from %s or an unechoed prompt, never from argv."
                         % SECRET_ENV)
    ap.add_argument("--admin", action="store_true",
                    help="read the catalog from /admin/services instead of "
                         "/rest/services. Needs a server administrator token, "
                         "and finds services that are stopped.")
    ap.add_argument("--no-probe", dest="no_probe", action="store_true",
                    help="skip the anonymous probe. Ghosts and orphans are "
                         "still reported, but nothing is proven about who can "
                         "read them.")
    ap.add_argument("--out", help="file to write the report to")
    ap.add_argument("--format", choices=["json", "csv"], default="json",
                    help="report format (default json)")
    ap.add_argument("--num", type=int, default=SEARCH_MAX_NUM,
                    help="rows per search page to ask for. Clamped to %d, "
                         "which is all the portal will give (default %d)."
                         % (SEARCH_MAX_NUM, SEARCH_MAX_NUM))
    ap.add_argument("--timeout", type=int, default=PROBE_TIMEOUT,
                    help="seconds to wait for one service probe (default %d)"
                         % PROBE_TIMEOUT)
    ap.add_argument("--max-partitions", dest="max_partitions", type=int,
                    default=MAX_PARTITIONS,
                    help="give up on the item enumeration after this many "
                         "partitions (default %d)" % MAX_PARTITIONS)
    ap.add_argument("--max-folders", dest="max_folders", type=int,
                    default=MAX_FOLDERS,
                    help="give up on the catalog walk after this many folders "
                         "(default %d)" % MAX_FOLDERS)
    ap.add_argument("--host-alias", dest="host_alias", action="append",
                    default=[], metavar="ITEMHOST=SERVERHOST",
                    help="treat portal items on ITEMHOST as items on "
                         "SERVERHOST, the host in --server. For items "
                         "registered under a public name. Repeatable. Bare "
                         "host names only.")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS certificate verification, for a deployment "
                         "behind an internal CA. Refused together with "
                         "--username.")
    ap.add_argument("--apply", action="store_true",
                    help="write the report file. Without this the reconcile "
                         "is printed and nothing is written.")
    ap.add_argument("--self-test", dest="self_test", action="store_true",
                    help="run the offline assertions and exit")
    return ap.parse_args(argv)


def _authenticate(args):
    """Return a token, or None for an anonymous read."""
    if args.token:
        return args.token
    if os.environ.get(TOKEN_ENV):
        return os.environ[TOKEN_ENV]
    if not args.username:
        return None
    secret = read_secret(args.username)
    return generate_token(args.portal, args.username, secret, args.insecure)


def main(argv=None):
    """Run the tool. Exit 0 clean, 1 findings, 2 unsure, 64 usage.

    Any exception the checks below did not foresee is reported on one line and
    exits 2. An uncaught one would exit 1 with a traceback, and 1 is the code
    for findings, so a scheduler would read a crash as a ghost list.
    """
    try:
        return _main(argv)
    except Exception as exc:
        # Only the type is printed. The message of an exception raised inside
        # urllib can quote a url, and the url carries the token.
        print("error: unexpected %s. This is a bug here or a response in a "
              "shape this tool does not know. No ghost list is given."
              % type(exc).__name__, file=sys.stderr)
        return 2


def _main(argv):
    args = _parse(sys.argv[1:] if argv is None else argv)

    if args.self_test:
        return self_test()

    if not args.server:
        print("error: --server is required. Use --self-test to verify the "
              "tool without a deployment.", file=sys.stderr)
        return 64
    if not args.portal:
        print("error: --portal is required. Without the item side every "
              "service on the server reconciles to a ghost.", file=sys.stderr)
        return 64
    for label, value in (("--server", args.server), ("--portal", args.portal)):
        if not is_http_url(value):
            print("error: %s must start with https:// or http://, got %r. "
                  "urllib quotes a url it cannot open back into its own "
                  "error, and that url carries the token."
                  % (label, sanitize_url(value)), file=sys.stderr)
            return 64
    if args.apply and not args.out:
        print("error: --apply needs --out, the file to write the report to.",
              file=sys.stderr)
        return 64
    if args.insecure and args.username:
        print("error: --insecure with --username would post your password "
              "down an unverified connection. Pass --token instead.",
              file=sys.stderr)
        return 64
    try:
        aliases = parse_host_aliases(args.host_alias)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 64
    if args.num < 1:
        print("error: --num must be at least 1.", file=sys.stderr)
        return 64
    if args.timeout < 1:
        print("error: --timeout must be at least 1 second.", file=sys.stderr)
        return 64
    if args.max_partitions < 1:
        print("error: --max-partitions must be at least 1.", file=sys.stderr)
        return 64
    if args.max_folders < 1:
        print("error: --max-folders must be at least 1.", file=sys.stderr)
        return 64

    try:
        token = _authenticate(args)
        root = server_root(args.server)
        print("server: %s" % root)
        services = walk_catalog(
            catalog_fetch(root, token, args.admin, args.insecure), root,
            args.max_folders)
        print("%d service(s) in the catalog" % len(services))

        query = args.query
        if not query:
            oid = org_id(args.portal, token, args.insecure)
            if not oid:
                raise RuntimeError("could not read the org id, pass --query")
            query = "orgid:%s" % oid
        print("portal: %s" % sanitize_url(args.portal))
        print("query: %s" % query)
        items, warnings = enumerate_items(
            portal_fetch(args.portal, token, args.insecure), base=query,
            now_ms=None, num=args.num, max_partitions=args.max_partitions,
            echo=lambda line: print(line))

        anonymous, details, probes = set(), {}, {}
        if not args.no_probe:
            print("probing %d service(s) with no token" % len(services))
            unanswered = set()
            anonymous, details = probe_all(services, args.insecure,
                                           args.timeout,
                                           echo=lambda line: print(line),
                                           unanswered=unanswered)
            probes = dict((svc["key"], svc["key"] not in unanswered)
                          for svc in services)
    except EnumerationIncomplete as exc:
        print("")
        print("error: the reconcile was abandoned, so no ghost list is given.",
              file=sys.stderr)
        print("  %s" % exc, file=sys.stderr)
        return 2
    except (RuntimeError, ValueError) as exc:
        # ValueError is how the pure layers reject data they cannot trust: a
        # catalog entry with no type, a search result with no id. Those come
        # from the deployment, not from a bug here.
        print("error: %s" % exc, file=sys.stderr)
        return 2

    report = reconcile(services, list(items.values()), anonymous, details,
                       probes, aliases)
    report.warnings.extend(warnings)

    print("")
    encoding = getattr(sys.stdout, "encoding", None)
    for line in describe(report):
        print(printable(line, encoding))

    if args.out:
        document = build_report(args.server, args.portal, query,
                                utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                                report)
        if not args.apply:
            print("")
            print("Check only. No report was written. Re-run with --apply.")
        else:
            writer = write_csv if args.format == "csv" else write_json
            print("")
            try:
                print("wrote %s" % writer(document, args.out))
            except OSError as exc:
                print("error: could not write %s: %s. Close the file if it is "
                      "open in another program, or choose another --out."
                      % (args.out, exc), file=sys.stderr)
                return 2

    return exit_code(report)


if __name__ == "__main__":
    sys.exit(main())

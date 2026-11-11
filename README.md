# ghostsvc

Reconcile portal items against federated server services, and name the anonymously accessible
services that appear in no sharing report.

Somebody publishes a service straight to the federated ArcGIS Server, from Pro or from Manager,
and never makes a portal item for it. Or an item is deleted while the service under it keeps
running. Either way the service is still up, and it answers anyone who knows the url. It is on no
sharing report, because a sharing report walks portal items and this service has none. You run the
audit and it comes back clean.

The service that costs you is usually the one nobody remembers publishing. A test copy of the
address points, made during a migration two years ago, still serving occupant names over the
internet to anybody who guesses `/rest/services/Address_TEST/FeatureServer/0/query?where=1=1`.

An excerpt of a real run. The lines marked `...` were left out, and the last line is the real
footer.

```
$ python ghostsvc.py --self-test
ghostsvc self-test: no server, no portal, no network, no token
--------------------------------------------------------------------
PASS  a plain rest url keys to host, folder-less name and type
...
PASS  http and https are the same service  <-- pinned defect
PASS  a short host and its fully qualified name are one machine  <-- pinned defect
...
PASS  an /arcgis web adaptor and a /server one front the same service  <-- pinned defect
...
PASS  a trailing slash is not a different service  <-- pinned defect
...
PASS  an explicit :6443 is the same service as the adaptor in front of it  <-- pinned defect
...
PASS  the admin catalog's Name.Type spelling meets the rest catalog's Name/Type  <-- pinned defect
...
PASS  case in the folder and service name is folded, because an item says roads/MapServer where the catalog says Roads/MapServer  <-- pinned defect
...
PASS  a portal item pointing at layer 3 is an item for that map service  <-- pinned defect
...
PASS  a query string is not part of the key, which is what keeps a token out of it  <-- pinned defect
...
PASS  a url carrying inline credentials keys to the service without them  <-- pinned defect
...
PASS  all eight differences at once still reconcile to one key  <-- pinned defect
PASS  a map service and a feature service of the same name are two services  <-- pinned defect
...
PASS  two federated servers each holding a Roads/MapServer are two services  <-- pinned defect
PASS  two servers on address literals stay apart, because shortening 10.0.0.5 to its first label would make them both '10'  <-- pinned defect
PASS  a non-default port is kept, because a second site on :8443 is a second service and merging it would hide a ghost  <-- pinned defect
...
PASS  a relative url names no host and is refused rather than keyed to an empty host that matches nothing  <-- pinned defect
...
PASS  the LAST rest/services wins, so a reverse proxy mounting the adaptor under a path of its own still keys the service  <-- pinned defect
...
PASS  folders are walked, not just the root  <-- pinned defect
...
PASS  a folder that lists itself is visited once, not for ever  <-- pinned defect
...
PASS  a catalog deeper than --max-folders refuses instead of walking on  <-- pinned defect
...
PASS  the admin catalog's serviceName and folderName give the same keys as the rest catalog  <-- pinned defect
PASS  and the url reported is always the REST one, because nobody without an admin token can open an admin url  <-- pinned defect
...
PASS  a service description returned with no token is ANONYMOUS  <-- pinned defect
...
PASS  a 200 carrying Token Required is NOT anonymous, which is how ArcGIS says no  <-- pinned defect
...
PASS  an HTTP 200 whose body is not JSON is NOT anonymous, because that is what an IWA or SAML login page looks like from here  <-- pinned defect
...
PASS  a catalog listing is not a service description, so a probe that landed on the wrong url is not counted as anonymous  <-- pinned defect
...
PASS  no probe url carries a token, which is the whole experiment  <-- pinned defect
...
PASS  an item whose url differs by scheme, host, adaptor, port, case, a doubled slash, a layer index and a trailing slash still matches its service  <-- pinned defect
PASS  a running service with no portal item is a GHOST  <-- pinned defect
...
PASS  a portal item whose service is not in the catalog is an ORPHAN  <-- pinned defect
...
PASS  a service that answers anonymously is a finding even though it has an item  <-- pinned defect
...
PASS  a service that answers anonymously AND has no item is the headline finding  <-- pinned defect
...
PASS  findings are ranked worst first: anonymous ghost, anonymous, ghost, orphan  <-- pinned defect
...
PASS  an empty portal makes every service a ghost, which is why an enumeration that refuses matters  <-- pinned defect
...
PASS  an item with no url and an item pointing at a web page are NOT orphans, because neither claims a service  <-- pinned defect
...
PASS  an item on the second federated server does not silence the ghost on the first  <-- pinned defect
...
PASS  an item on another domain with the same first label does not hide the ghost, and reads as an orphan  <-- pinned defect
...
PASS  a probe that got no definite answer from any service exits 2, not 0  <-- pinned defect
...
PASS  a ghost whose probe could not ask is recorded as unknown, not as not anonymous  <-- pinned defect
...
PASS  a user:password@ in a url does not survive sanitising  <-- pinned defect
...
PASS  a password holding 'Hunter/2pw' is removed whole  <-- pinned defect
...
PASS  an @ in a query parameter is not a credential separator, so the token after it is not printed  <-- pinned defect
...
PASS  the guarded lead characters are exactly = + - @ tab and carriage return, written out here so the constant cannot shrink unseen  <-- pinned defect
PASS  a cell led by =, +, -, @, tab or carriage return gets one apostrophe  <-- pinned defect
...
PASS  a cell already led by the apostrophe is not prefixed twice
...
PASS  the key column is guarded for =, +, -, @, tab and carriage return  <-- pinned defect
PASS  the service_url column is guarded for =, +, -, @, tab and carriage return  <-- pinned defect
PASS  the folder column is guarded for =, +, -, @, tab and carriage return  <-- pinned defect
...
PASS  the item_access column is guarded for =, +, -, @, tab and carriage return  <-- pinned defect
PASS  severity stays a plain number and kind and anonymous are untouched
...
PASS  a password the server echoes back form-encoded or percent-encoded is redacted too  <-- pinned defect
...
PASS  exactly 10,000 is the CAP and never a total  <-- pinned defect
...
PASS  a short page advances by the ten rows it got, not by the hundred it asked for  <-- pinned defect
...
PASS  a one day partition with nothing left to split on REFUSES  <-- pinned defect
PASS  and the refusal says what an incomplete enumeration would do to the ghost list  <-- pinned defect
...
PASS  the default opener verifies the certificate  <-- pinned defect
...
PASS  a service that answers a probe with a login page is NOT reported anonymous  <-- pinned defect
...
PASS  the token in the url urllib quoted back is redacted out of the error  <-- pinned defect
...
PASS  the referer posted to the portal carries no password and no token from the --portal url  <-- pinned defect
...
PASS  the portal's error code is reported and the dead token is not  <-- pinned defect
...
PASS  the anonymously reachable service with no item is reported  <-- pinned defect
...
PASS  the web map is reported as unreconciled rather than as an orphan  <-- pinned defect
...
PASS  one service down for the probe and no finding exits 2, not 0  <-- pinned defect
...
PASS  --no-probe with nothing to report does not claim that none answered anonymously  <-- pinned defect
...
PASS  a probed run still records an orphan as unknown, because an orphan's url was never asked  <-- pinned defect
PASS  a report that cannot be written exits 2 with a message, not 1 with a traceback  <-- pinned defect
PASS  a password in --server and a token in --portal are not echoed  <-- pinned defect
...
PASS  a token in GHOSTSVC_TOKEN is used when --token is absent
...
PASS  no credential reaches the report file on disk  <-- pinned defect
...
PASS  an enumeration that could not be completed exits 2 and reports no ghosts at all  <-- pinned defect
...
PASS  and the report from the previous run was not overwritten by a refused one  <-- pinned defect
...
PASS  a server whose catalog will not answer exits 2 rather than reporting every item as an orphan  <-- pinned defect
...
PASS  a --username run with no password and no terminal exits 2 with a message, not 1 with a traceback  <-- pinned defect
PASS  an exception nothing foresaw exits 2, not 1 which means findings, and prints its type but not its message, which can carry a url with a token  <-- pinned defect
...
PASS  a --server with no --portal is a usage error, because every service would be a ghost  <-- pinned defect
...
PASS  an unknown flag is a usage error, exit 64, not argparse's 2  <-- pinned defect
...
PASS  a unique prefix of the write flag is refused, because argparse would otherwise take --ap for --apply  <-- pinned defect
...
PASS  a plausible-looking --unpublish is refused, because this tool changes nothing  <-- pinned defect
...
PASS  the harness records a false check, a missing exception, two wrong exceptions, an argv argparse accepted, two bad enumerations, four bad url comparisons and three bad calls as thirteen failures, so a broken tool turns this self-test red  <-- pinned defect
--------------------------------------------------------------------
566 assertions, 0 failed
```

## Requirements

Python 3.9 or newer. The final file's self-test ran green on 3.11.8, 3.12 and 3.13. An earlier revision ran green on 3.9.25, and no 3.9 interpreter was at hand for the last edits, which use nothing newer than 3.9. Standard library only: `urllib`, `json`, `os`, `sys`, `ssl`, `io`, `csv`,
`time`, `argparse`, `datetime`, `getpass`, and `re`, `tempfile`, `shutil` and `runpy` in the self-test. It
runs on ArcGIS Pro's Python and on a plain `python3`. `arcpy` is not used and the `arcgis` package
is not needed.

```
git clone https://github.com/uhsear/ghostsvc.git
python ghostsvc.py --self-test
```

`--self-test` needs no server, no portal, no network and no credentials. You can check the tool
before you point it at a deployment. It covers the network paths as well as the decisions. The
catalog walk, the item paging, sign-in, an expired token, an HTTP error, a 200 carrying an ArcGIS
error envelope and the whole command line all run against a stand-in deployment. That deployment
answers inside the process, and no socket is opened. The shipped self-test therefore never
exercises the real `urllib` and TLS path. The CSV example below came from a separate, one-off run
against a local `http.server`, and that stub is not part of this repository.

## Usage

Point it at the federated server and at the portal that is supposed to own its services.

```
export GHOSTSVC_PASSWORD='...'
python ghostsvc.py --server https://gis.example.com/arcgis \
    --portal https://portal.example.com/portal --username gis_admin
```

Keep the answer:

```
export GHOSTSVC_TOKEN='...'
python ghostsvc.py --server https://gis.example.com/arcgis \
    --portal https://portal.example.com/portal \
    --out ghosts.csv --format csv --apply
```

| Flag | Default | What it does |
|---|---|---|
| `--server` | none | Federated server url. Required. `/rest/services` on the end is trimmed. |
| `--portal` | none | Portal url. Required, because without the item side every service is a ghost. |
| `--query` | org id | Search query for the item side. Defaults to `orgid:` of the signed-in org. |
| `--token` | none | An existing portal token. It sits in the process list and in shell history, so export `GHOSTSVC_TOKEN` instead. The flag wins when both are set. |
| `--username` | none | Generate a token for this user. |
| `--admin` | off | Read the catalog from `/admin/services`. Needs a server administrator token, and finds stopped services. |
| `--no-probe` | off | Skip the anonymity probe. Ghosts and orphans are still reported. |
| `--out` | none | File to write the report to. |
| `--format` | `json` | `json` or `csv`. |
| `--num` | `100` | Search rows per page. Clamped to 100, which is all the portal gives. |
| `--timeout` | `20` | Seconds to wait for one service probe. |
| `--max-partitions` | `4096` | Give up on the item enumeration rather than bisecting for ever. |
| `--max-folders` | `512` | Give up on the catalog walk rather than following a folder loop. |
| `--host-alias` | none | `ITEMHOST=SERVERHOST`. Treat portal items on `ITEMHOST` as items on `SERVERHOST`, for items registered under a public host name. Bare host names only. Repeatable. Used for matching only. |
| `--insecure` | off | Skip TLS verification. Refused together with `--username`. |
| `--apply` | off | Write the report file. Without it nothing is written. |
| `--self-test` | off | Run the offline assertions and exit. |

There is no `--password` flag, and there never will be. `argv` is readable by every process on the
machine, and it lands in shell history and in scheduler logs. The password comes from
`GHOSTSVC_PASSWORD` or from an unechoed prompt. A token has the same exposure, so it can come
from `GHOSTSVC_TOKEN` as well as from `--token`. No report holds either. Every error message is
stripped of it before it is printed, because `generateToken` is a POST and urllib repeats the
request in some of its exceptions. The token gets the same treatment. A token travels as a query
parameter, and urllib answers a url it cannot open by quoting that whole url back.

## What it reports

Four kinds over three ideas. GHOST is a running service with no portal item. ORPHAN is a portal
item whose service is not in the catalog. ANONYMOUS is a service that answered a request carrying
no token. A service that is both a ghost and anonymous is reported once, at the top.

```
[100] anonymous-ghost  https://gis.example.com/arcgis/rest/services/Transport/Rail/MapServer
        answered with currentVersion and no token
[ 80] anonymous        https://gis.example.com/arcgis/rest/services/Parcels/FeatureServer
        answered with currentVersion and no token
        - Parcels (Feature Service, public) 0c94a2e5f1b7480d9e22a6c3d5f81b47
[ 50] ghost            https://gis.example.com/arcgis/rest/services/Hydrants/FeatureServer
        499 Token Required
[ 20] orphan           https://gis.example.com/arcgis/rest/services/Deleted/MapServer
        - Deleted layer (Map Service, org) 0a6cf1b79c2d4e0d9f3b8a71e5c4d2f6
```

`anonymous` is the audit deliverable, and it is an observation rather than a reading of a
configuration field. The tool opens the service url with no token and looks at what came back. A
service can be configured private on the server and still answer. The web adaptor in front of it
was installed without web tier authentication, and the permissions page will not tell you that.
It counts as anonymous only when the response looks like a service description. A deployment
behind IWA or SAML answers an unauthenticated request with HTTP 200 and a login page, so "the
request did not fail" proves nothing.

A probe can also fail to ask. A service that is down, an HTTP 500 and an error nobody recognises
leave the question open. Those services are recorded as unknown: the `anonymous` column is empty
and the JSON value is `null`. A run with no finding exits 2 when even one service could not be
probed, because that service might be open to everyone, and it never prints that nothing answered
anonymously. An orphan is never probed, because its url names no service on this server, so its
`anonymous` value is always unknown. `--no-probe` leaves every ghost unknown for the same reason.

## Why not the tools that already exist

ArcGIS Server Manager lists every service on the server, folder by folder, in a browser. It is
accurate and it is supported. The ArcGIS API for Python reads the same list in two lines with
`server.services.list()`, and `gis.content.search()` reads the item list beside it. Both are the
right tools for reading either side.

Neither one joins the two lists, and the join is the job. Manager has no idea which services have
portal items, because that is the portal's business, and the portal's item list has no idea which
services exist, because that is the server's. The answer nobody has is the difference between
them.

Manager will also show you a service's permissions. That is a configuration field, not an
observation, and on a federated deployment the two disagree more often than anyone expects. This
tool asks the service itself, with no token, and writes down what came back.

An organization content report is the other honest answer, and it has the same shape of gap. It is
a row per item. A service with no item has no row.

## The part that is actually hard

The reconcile is a set difference. The engineering is the key it runs on.

Two urls for one service differ in eight ways. The scheme. The short host against the fully
qualified one. The web adaptor name. A trailing or doubled slash. Case in the folder and service
name. An explicit `:6443` or `:443`. A layer index on the end. And `/rest/services` against
`/admin/services`, which also spells the service `Name.Type` instead of `Name/Type`. A portal item
registered from inside the network is almost never spelled like the catalog entry the server
publishes. All of it has to fold to one key:

```
http://GIS:6443/server/rest//services/TRANSPORT/roads/mapserver/2/
https://gis.example.org/arcgis/rest/services/Transport/Roads/MapServer
                                   -> gis/transport/roads/MapServer
```

Get that wrong and every service on the server is a ghost. Twenty-three assertions cover pairs of
urls that must come out equal, and eight cover pairs that must stay apart. The second set gets the
same attention as the first, because a key that merges two real services hides every ghost on the
second one. Two
federated servers each holding a `Roads/MapServer` stay apart. So do `10.0.0.5` and `10.0.0.6`,
which is why an address literal is never shortened to its first label. So does a second site on
`:8443`, because only the four ArcGIS defaults, 80, 443, 6080 and 6443, carry no information.

Case is folded, and that is a decision rather than an obvious truth. Leaving case alone reports
`Roads/MapServer` as a ghost because the item says `roads/MapServer`. Esri's documentation does
not say whether a server may hold two services in one folder that differ only by case, and this
tool does not assume it. A server that held both would see them reported as one.

The host is folded to its first label for the same reason, and that fold has a limit.
`gis.alpha.example.org` and `gis.beta.example.net` both fold to `gis`. When the service and the
item each name a domain and the domains differ, they are different machines: the service is a
ghost and the item is an orphan. A short host such as `gis` names no domain, so it matches a
service with that first label whatever its domain.

A url it cannot read is refused rather than guessed at. That covers a portal item page, a query
endpoint, a url with no host, and a url ending in something that is not an ArcGIS service type.
All of them count as unreadable and are reported as a number, because a key built from a guess is
a ghost that does not exist.

## What it refuses

It never changes anything on the server or in the portal. The calls it makes are `rest/services`, `admin/services`,
`sharing/rest/search`, `portals/self` and `generateToken`, and the self-test asserts that a
plausible-looking `--unpublish` and `--delete-ghosts` are rejected rather than ignored.

It refuses to produce a ghost list from an item enumeration it cannot prove is complete. `search`
counts accurately only to 10,000 and will not page past it. The enumeration therefore bisects by
created date and then by item type, until every slice is provably under the cap, the way
[itemcensus](https://github.com/uhsear/itemcensus) does. If a slice still reports the cap with
nothing left to split it on, the run stops with exit code 2 and no list.

This matters more here than in a census. A census that stops at 10,000 reports a number that is
too low. A reconcile that stops at 10,000 reports every item above the cap as a ghost service. The
failure mode of a half-read portal is a confident page of services to investigate, all of which
are fine.

It refuses the same way when the catalog walk cannot finish, and when `--portal` is missing.

## The CSV file

`--format csv` writes one row per finding per item. A spreadsheet runs a cell that starts with
`=`, `+`, `-` or `@`. OWASP also lists a leading tab and carriage return among the characters a
cell should not start with. Every text in this report was typed by someone else: a service name, a folder, an item title, an item owner.
A service named `=cmd` or an item titled `@evil` would otherwise run on the machine of whoever
opens the report. Every text column therefore gets one leading apostrophe when it starts with one of
those six characters. `severity` stays a plain number, and `kind` and `anonymous` are written by
this tool, so they are not touched. Only the CSV is guarded. The JSON report carries the raw text.

```
kind,severity,key,service_url,folder,name,type,anonymous,detail,item_id,item_title,item_owner,item_type,item_access
anonymous-ghost,100,127.0.0.1:8831/=cmd/MapServer,http://127.0.0.1:8831/arcgis/rest/services/%3Dcmd/MapServer,,'=cmd,MapServer,yes,answered with currentVersion and no token,,,,,
orphan,20,127.0.0.1:8831/gone/FeatureServer,http://127.0.0.1:8831/arcgis/rest/services/Gone/FeatureServer,,,,,,abc,'@evil,'+owner,Feature Service,public
```

That is the header and two rows of the output of a real run of `main()` over a socket against a
local `http.server` stand-in, with a service named `=cmd` and an item titled `@evil` owned by
`+owner`. The service url shows `%3Dcmd` because the tool percent-encodes every catalog name. The `name` column keeps the raw text and is the guarded cell. The orphan's `anonymous` cell is empty because an orphan is never probed. The stand-in
script is not part of this repository. The self-test has one assertion for each of
the eleven text columns, and each one tries all six characters. They are written out as a literal
tuple in the test, so shrinking the constant in the tool turns the self-test red. The tool never reads its own CSV
back, so there is nothing to un-prefix. If you load the file into a script, strip one leading
apostrophe from a cell that starts with `'` followed by one of the six characters.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Every service has a portal item and none answered without a token. Also: `--no-probe` was given and there is no ghost or orphan. |
| 1 | There are findings to review. A finding wins over an unanswered probe. |
| 2 | The server or the portal could not be read, so no list is given. Also: the report file could not be written, there is no finding and at least one service could not be probed, there is no finding and the enumeration warned, the password could not be asked for, or an exception the tool did not foresee ended the run. |
| 64 | Usage error, including an unknown flag or a bad value. |

## Limits

- It compares one server against one portal. A deployment with several federated servers needs one
  run per server, and an item pointing at the other server reads as an orphan in each. Two servers
  on different domains that share a first label are kept apart only when the item names its
  domain.
- ArcGIS Online hosted services are out of scope. Their urls carry the org hash in the position
  this tool treats as the web adaptor name, so two organizations would collide. Use it on
  federated Enterprise servers.
- A non-default port is part of the key. A site reachable on both `:443` and `:8443` reports the
  `:8443` services as ghosts. The port is in the key the finding prints, so it is visible.
- `--no-probe` leaves the anonymity column empty. Without the probe the tool reports what the
  portal and the server disagree about, and nothing about who can read it. With no finding it
  exits 0 and says the probe was not run. You asked it not to look, so that exit 0 means nothing
  was disproved, not that the org is clean.
- The probe is one GET per service, done in sequence. A catalog with thousands of services takes
  as long as that sounds. `--timeout` is per service.
- A service that is down during the probe is recorded as unknown, not as not anonymous. It may
  well be anonymous when it comes back. The summary counts them. If some answered and some did
  not, the run exits 2 when there is no finding and 1 when there is one, so read that count.
- Anonymous means the service description answered. It does not mean the data answered. A service
  can return its metadata to anybody and refuse a query, which is unusual but real.
- The walk recurses to any depth, whatever the server allows, and stops on a folder it has already
  visited, because a reverse proxy can produce a listing that points back at itself.
- Esri's documentation does not say whether `/rest/services` lists a stopped service. `--admin`
  reads the admin catalog instead, which needs a server administrator token. A stopped service
  cannot service requests, so it will not answer the probe.
- It cannot say who published a ghost, or when. ArcGIS Server records that in its own logs, which
  are per-deployment and roll over.
- An orphan may be a service that is merely stopped rather than gone. Run with `--admin` to tell
  those apart.
- `--insecure` skips certificate verification and exists for deployments behind an internal CA. It
  is off by default and refused together with `--username`, because posting a password down an
  unverified connection is the failure it would cause. Add the CA to your trust store instead.
- The item side is every item the query matches, not only service items. A list of service item
  types kept in this file would go stale, and a missing type reads as a ghost. On a large
  organization `--query` makes the run faster, at the cost of the items the query leaves out.
- The guard covers the six characters named above. OWASP also lists a leading line feed and the
  full-width forms of `=`, `+`, `-` and `@`, and none of those is guarded. OWASP also warns that a
  quote prefix is unreliable in Excel once the file is saved and opened again. Open the report, do not
  round-trip it.
- The guard applies to the CSV only. The JSON report carries the raw text.
- A non-text value in a text column is written as its text, so a `None` would read as `None`.
  Portal records never carry one, because a missing title or owner becomes an empty string first.
- Item titles and service names are printed to the terminal as they are, so a control or escape
  character in published text reaches the console.
- A token or password inside the url you pass as `--server` or `--portal`, or inside an item's url,
  is dropped before anything is requested, printed or written, including the `referer` posted to
  `generateToken`. The credential is cut at the last `@`, so a password that holds `/`, `?` or `#`
  goes too. It never authenticates, so use a token. An `@` that follows a `?` or `#` with a `=` or `&`
  between them is a query parameter, such as `?e=a@b.com`, not a credential separator, so the
  query is dropped whole and the token in it goes too. A password that holds `?` and then a `=` or
  `&` before its `@` is read as a query and keeps its first part. An `@` in the path of a url that
  has a port, such as `host:6443/svc@x`, is read as a credential separator and the host is cut off,
  so that item reads as unreadable or as a false orphan. Esri service names rarely hold an `@`.
- A password that the server echoes back in an error is removed in its plain, form-encoded and
  percent-encoded spellings. Any other encoding is not recognised.
- A server that answers with an HTTP redirect to another host gets the token, because `urllib`
  follows it with the query string intact. The probe follows redirects too, without a token. A
  server that redirects a probe or a catalog call sends the request to whatever host its `Location`
  header names, so point `--server` and `--portal` only at hosts you trust.
- Folder and service names come from the catalog and are percent-encoded one segment at a time before
  they go into a request path, so a space, a non-ASCII letter, `?` or `#` stays inside its segment.
  A name that is exactly `..` is not encoded and changes the path requested on the server host,
  never the host.
- The window ends at the client's clock. An item the portal created a moment after that reading is
  missed, and its service reads as a ghost. That is the safe direction, and a re-run clears it.
- A run that only has enumeration warnings exits 2 when it has no finding, and says that it is not a
  clean result. Missing items can only add false ghosts, but an orphan could go unseen, so read the
  warnings and run again.
- A catalog read with a token that cannot see every service reports only the services that token
  may list. An empty catalog next to an empty portal exits 0 and prints the sentence that every
  service has an item, which is vacuous for zero services.
- The item side comes from `search`, and Esri says "The results of a search only contain items that
  the user has permission to access". A run with a token that cannot see an item reports that
  item's service as a ghost, although the item exists. Run with a token that sees every item, such
  as an administrator's, before you act on a ghost.
- `--self-test` makes a temporary directory and a temporary CSV outside `--apply`, and removes them
  afterwards. Nothing else the tool does writes without `--apply`.
- The shipped self-test drives the network code through an in-process stand-in, not a socket. The
  real HTTP path was checked by hand against a local `http.server`: a full run with `--token`
  and a `--username` sign-in whose posted `referer` carried no credential. That stand-in is not in
  this repository. The end-to-end runs in the self-test do not cover `generateToken` over a socket,
  `--admin`, `--insecure`, the date bisect or the 10,000 refusal.
- These three Esri behaviours rest on observation and are not cited to an Esri page: the HTTP 200
  with error 499 `Token Required`, the default ports 80, 443, 6080 and 6443, and whether
  `/rest/services` lists a stopped service.
- A cell with leading whitespace before a formula character is not guarded. The strip rule cannot
  distinguish a guarded cell from source text that began with an apostrophe.
- Import the CSV as UTF-8 in Excel. The file has no byte order mark, so a double-click may show
  non-ASCII titles as mojibake.
- A response in a shape the tool does not expect ends the run with one line, `error: unexpected
  <type>`, and exit 2. The line names the exception type and not its message, because a message
  from `urllib` can quote a url that carries the token.
- A `--username` run with no `GHOSTSVC_PASSWORD` and no stdin exits 2 with a message. A Windows
  console prompt from `getpass` reads the console, not a redirected stdin, and can wait for ever
  under a scheduler, so set `GHOSTSVC_PASSWORD` there.
- `--username` posts the password to the scheme of `--portal`. An `http://` portal sends it in clear
  text. Only `--insecure` is refused with `--username`, so use an `https://` portal.
- `--token` puts a token on the command line, where other processes can read it. Use
  `GHOSTSVC_TOKEN`. The token travels in the query string of every request, which is how the Esri
  `token` parameter works, so it lands in server and proxy access logs.
- A lone surrogate in a title, from a JSON `\ud800`, fails while the CSV is written. The run ends
  with `error: unexpected UnicodeEncodeError` and exit 2, and the report file is cut short.
- `--out` truncates an existing file before it writes, so a write that fails destroys the previous
  report. Keep the last one under another name.
- The CSV carries neither the warnings nor the count of unreadable items. They are in the JSON and
  on the console, so a CSV from a run that exited 2 on warnings looks complete.
- A cell is guarded by its first character. A text such as the item title `-5` becomes the text
  `'-5`, never a number. Only `severity` stays numeric. A leading line feed, a full-width `=`, `+`,
  `-` or `@`, and a formula character after a space, are not guarded.
- A service type that is not in the tool's list of ArcGIS service types stops the run with exit 2,
  because the key cannot be built. That is a refusal, not a guess. Add the type to `SERVICE_TYPES`.
- The self-test parses `--admin` and `--insecure` and runs the admin catalog call and an
  `insecure` call against the in-process stand-in. It makes no TLS connection and runs no whole
  `--admin` run, so those two are not exercised end to end. A one-off run of `--token`, `--apply`
  and `--format csv` over a socket against a local `http.server` produced the CSV example above.
  That stub is not in this repository, so you cannot repeat that run from it.
- Coverage is 100 percent of branches on Windows 3.13, 1873 statements and 374 branches, with no
  line left out. Linux was run without the coverage module, so the Linux run proves the assertions
  and not the percentage. The Windows 3.11, Windows 3.12, Windows 3.13 and Linux 3.12 runs print the same
  assertion count, 566, because the self-test does not branch on the host.

## Sources

- Python `csv` module, `newline=''` on the file object:
  https://docs.python.org/3/library/csv.html
- Formula characters and the apostrophe mitigation, including the line feed and full-width cases
  this tool does not guard: https://owasp.org/www-community/attacks/CSV_Injection
- `search` returns `num` up to 100 and makes only the top 10,000 results reachable by paging, and its
  results only contain items the user has permission to access:
  https://developers.arcgis.com/rest/users-groups-and-items/search/
- `generateToken` is a POST to `/sharing/rest/generateToken` taking `username`, `password`,
  `client`, `referer` and `expiration`:
  https://developers.arcgis.com/rest/users-groups-and-items/generate-token/
- `portals/self` returns the organization `id`:
  https://developers.arcgis.com/rest/users-groups-and-items/portal-self/
- The admin services listing carries `folderName` and `serviceName`:
  https://developers.arcgis.com/rest/enterprise-administration/server/services/
- A stopped service "cannot service any incoming requests":
  https://developers.arcgis.com/rest/enterprise-administration/server/stopservice/

Not verified against Esri documentation, and stated here as this tool's behaviour: that ArcGIS
answers a tokenless request with HTTP 200 and an error 499 `Token Required`, that 80, 443, 6080 and
6443 are the ports to treat as defaults, and whether `/rest/services` lists a stopped service.
The pages that would settle the first two could not be fetched when this was written, and the Esri ports page failed to load again on 2026-11-11.

## Contributing

Open an issue or pull request on GitHub.

## Author

Built by [Asir Khan](https://www.linkedin.com/in/asir-khan-310317264/).

## License

MIT.

## Related

Other single-file tools in this portfolio that pair with this one:

- [sharewatch](https://github.com/uhsear/sharewatch) - the sharing posture of the items this reconciles against
- [itemcensus](https://github.com/uhsear/itemcensus) - the enumeration underneath this
- [sightline](https://github.com/uhsear/sightline) - broken sharing from the viewer's side

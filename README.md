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

```
$ python ghostsvc.py --self-test
ghostsvc self-test: no server, no portal, no network, no token
--------------------------------------------------------------------
PASS  a plain rest url keys to host, folder-less name and type
PASS  http and https are the same service  <-- pinned defect
PASS  a short host and its fully qualified name are one machine  <-- pinned defect
PASS  an /arcgis web adaptor and a /server one front the same service  <-- pinned defect
PASS  a trailing slash is not a different service  <-- pinned defect
PASS  an explicit :6443 is the same service as the adaptor in front of it  <-- pinned defect
PASS  the admin catalog's Name.Type spelling meets the rest catalog's Name/Type  <-- pinned defect
PASS  case in the folder and service name is folded, because ArcGIS Server will not publish two services that differ only by it  <-- pinned defect
PASS  a portal item pointing at layer 3 is an item for that map service  <-- pinned defect
PASS  a query string is not part of the key, which is what keeps a token out of it  <-- pinned defect
PASS  a url carrying inline credentials keys to the service without them  <-- pinned defect
PASS  all eight differences at once still reconcile to one key  <-- pinned defect
PASS  a map service and a feature service of the same name are two services  <-- pinned defect
PASS  two federated servers each holding a Roads/MapServer are two services  <-- pinned defect
PASS  two servers on address literals stay apart, because shortening 10.0.0.5 to its first label would make them both '10'  <-- pinned defect
PASS  a non-default port is kept, because a second site on :8443 is a second service and merging it would hide a ghost  <-- pinned defect
PASS  a relative url names no host and is refused rather than keyed to an empty host that matches nothing  <-- pinned defect
PASS  the LAST rest/services wins, so a reverse proxy mounting the adaptor under a path of its own still keys the service  <-- pinned defect
...
PASS  folders are walked, not just the root  <-- pinned defect
PASS  a folder that lists itself is visited once, not for ever  <-- pinned defect
PASS  a catalog deeper than --max-folders refuses instead of walking on  <-- pinned defect
PASS  the admin catalog's serviceName and folderName give the same keys as the rest catalog  <-- pinned defect
PASS  and the url reported is always the REST one, because nobody without an admin token can open an admin url  <-- pinned defect
...
PASS  a service description returned with no token is ANONYMOUS  <-- pinned defect
PASS  a 200 carrying Token Required is NOT anonymous, which is how ArcGIS says no  <-- pinned defect
PASS  an HTTP 200 whose body is not JSON is NOT anonymous, because that is what an IWA or SAML login page looks like from here  <-- pinned defect
PASS  a catalog listing is not a service description, so a probe that landed on the wrong url is not counted as anonymous  <-- pinned defect
PASS  no probe url carries a token, which is the whole experiment  <-- pinned defect
...
PASS  an item whose url differs by scheme, host, adaptor, port, case, a doubled slash, a layer index and a trailing slash still matches its service  <-- pinned defect
PASS  a running service with no portal item is a GHOST  <-- pinned defect
PASS  a portal item whose service is not in the catalog is an ORPHAN  <-- pinned defect
PASS  a service that answers anonymously is a finding even though it has an item  <-- pinned defect
PASS  a service that answers anonymously AND has no item is the headline finding  <-- pinned defect
PASS  findings are ranked worst first: anonymous ghost, anonymous, ghost, orphan  <-- pinned defect
PASS  an empty portal makes every service a ghost, which is why an enumeration that refuses matters  <-- pinned defect
PASS  an item with no url and an item pointing at a web page are NOT orphans, because neither claims a service  <-- pinned defect
PASS  an item on the second federated server does not silence the ghost on the first  <-- pinned defect
...
PASS  exactly 10,000 is the CAP and never a total  <-- pinned defect
PASS  a short page advances by the ten rows it got, not by the hundred it asked for  <-- pinned defect
PASS  a one day partition with nothing left to split on REFUSES  <-- pinned defect
PASS  and the refusal says what an incomplete enumeration would do to the ghost list  <-- pinned defect
...
PASS  the default opener verifies the certificate  <-- pinned defect
PASS  a service that answers a probe with a login page is NOT reported anonymous  <-- pinned defect
PASS  the token in the url urllib quoted back is redacted out of the error  <-- pinned defect
PASS  the portal's error code is reported and the dead token is not  <-- pinned defect
...
PASS  the anonymously reachable service with no item is reported  <-- pinned defect
PASS  the web map is reported as unreconciled rather than as an orphan  <-- pinned defect
PASS  no credential reaches the report file on disk  <-- pinned defect
PASS  an enumeration that could not be completed exits 2 and reports no ghosts at all  <-- pinned defect
PASS  and the report from the previous run was not overwritten by a refused one  <-- pinned defect
PASS  a server whose catalog will not answer exits 2 rather than reporting every item as an orphan  <-- pinned defect
PASS  a --server with no --portal is a usage error, because every service would be a ghost  <-- pinned defect
...
PASS  a unique prefix of the write flag is refused, because argparse would otherwise take --ap for --apply  <-- pinned defect
PASS  a plausible-looking --unpublish is refused, because this tool changes nothing  <-- pinned defect
PASS  the harness records a false check, a missing exception, two wrong exceptions, an argv argparse accepted, two bad enumerations, four bad url comparisons and three bad calls as thirteen failures, so a broken tool turns this self-test red  <-- pinned defect
--------------------------------------------------------------------
446 assertions, 0 failed
```

## Requirements

Python 3.9 or newer. Standard library only: `urllib`, `json`, `os`, `sys`, `ssl`, `io`, `csv`,
`time`, `argparse`, `datetime`, `getpass`, and `re`, `tempfile` and `shutil` in the self-test. It
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
answers inside the process, and no socket is opened.

## Usage

Point it at the federated server and at the portal that is supposed to own its services.

```
export GHOSTSVC_PASSWORD='...'
python ghostsvc.py --server https://gis.example.com/arcgis \
    --portal https://portal.example.com/portal --username gis_admin
```

Keep the answer:

```
python ghostsvc.py --server https://gis.example.com/arcgis \
    --portal https://portal.example.com/portal --token TOKEN \
    --out ghosts.csv --format csv --apply
```

| Flag | Default | What it does |
|---|---|---|
| `--server` | none | Federated server url. Required. `/rest/services` on the end is trimmed. |
| `--portal` | none | Portal url. Required, because without the item side every service is a ghost. |
| `--query` | org id | Search query for the item side. Defaults to `orgid:` of the signed-in org. |
| `--token` | none | An existing portal token. |
| `--username` | none | Generate a token for this user. |
| `--admin` | off | Read the catalog from `/admin/services`. Needs a server administrator token, and finds stopped services. |
| `--no-probe` | off | Skip the anonymity probe. Ghosts and orphans are still reported. |
| `--out` | none | File to write the report to. |
| `--format` | `json` | `json` or `csv`. |
| `--num` | `100` | Search rows per page. Clamped to 100, which is all the portal gives. |
| `--timeout` | `20` | Seconds to wait for one service probe. |
| `--max-partitions` | `4096` | Give up on the item enumeration rather than bisecting for ever. |
| `--max-folders` | `512` | Give up on the catalog walk rather than following a folder loop. |
| `--insecure` | off | Skip TLS verification. Refused together with `--username`. |
| `--apply` | off | Write the report file. Without it nothing is written. |
| `--self-test` | off | Run the offline assertions and exit. |

There is no `--password` flag, and there never will be. `argv` is readable by every process on the
machine, and it lands in shell history and in scheduler logs. The password comes from
`GHOSTSVC_PASSWORD` or from an unechoed prompt. No report holds it. Every error message is
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

Case is folded, and that is a decision rather than an obvious truth. ArcGIS Server will not
publish two services in one folder whose names differ only by case, so folding cannot merge two
real services. Leaving case alone reports `Roads/MapServer` as a ghost because the item says
`roads/MapServer`. If your deployment somehow holds both, this tool reports them as one.

A url it cannot read is refused rather than guessed at. That covers a portal item page, a query
endpoint, a url with no host, and a url ending in something that is not an ArcGIS service type.
All of them count as unreadable and are reported as a number, because a key built from a guess is
a ghost that does not exist.

## What it refuses

It never changes anything. The calls it makes are `rest/services`, `admin/services`,
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

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Every service has a portal item and none answered without a token. |
| 1 | There are findings to review. |
| 2 | The server or the portal could not be read, so no list is given. |
| 64 | Usage error. |

## Limits

- It compares one server against one portal. A deployment with several federated servers needs one
  run per server, and an item pointing at the other server reads as an orphan in each.
- ArcGIS Online hosted services are out of scope. Their urls carry the org hash in the position
  this tool treats as the web adaptor name, so two organizations would collide. Use it on
  federated Enterprise servers.
- A non-default port is part of the key. A site reachable on both `:443` and `:8443` reports the
  `:8443` services as ghosts. The port is in the key the finding prints, so it is visible.
- `--no-probe` leaves the anonymity column empty. Without the probe the tool reports what the
  portal and the server disagree about, and nothing about who can read it.
- The probe is one GET per service, done in sequence. A catalog with thousands of services takes
  as long as that sounds. `--timeout` is per service.
- A service that is down during the probe is recorded as not anonymous. It may well be anonymous
  when it comes back. The reason column says the request failed, so those are worth re-running.
- Anonymous means the service description answered. It does not mean the data answered. A service
  can return its metadata to anybody and refuse a query, which is unusual but real.
- ArcGIS Server folders are one level deep. The walk recurses anyway, and stops on a folder it has
  already visited, because a reverse proxy can produce a listing that points back at itself.
- `/rest/services` lists only started services. `--admin` reads the catalog that lists the
  stopped ones too, which needs a server administrator token. A stopped service is still a ghost
  worth knowing about, and it will not answer the probe.
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

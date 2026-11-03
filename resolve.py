"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

ROOT_SERVERS = ("198.41.0.4",
                "199.9.14.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")

# ---------------------------------------------------------------------------
# Global Caching Structures
# ---------------------------------------------------------------------------
# Cache 1: Exact matches for (name_str, qtype_int) -> dns.message.Message
EXACT_CACHE = {}

# Cache 2: Intermediate NS delegations for domain suffixes
# e.g., "edu." -> ["192.5.6.30", ...]
DELEGATION_CACHE = {}


def send_query(target_name: dns.name.Name, qtype: dns.rdata.Rdata, server_ip: str):
    """
    Helper function to send a single DNS query with a strict 3-second timeout.
    Catches all exceptions so the program never dumps a stacktrace.
    """
    try:
        outbound_query = dns.message.make_query(target_name, qtype)
        return dns.query.udp(outbound_query, server_ip, timeout=3.0)
    except Exception:
        # Catch timeouts, connection refused, or socket errors
        return None


def recursive_resolve(target_name: dns.name.Name, qtype: dns.rdata.Rdata, server_ips: list, visited: set) -> dns.message.Message:
    """
    Core recursive engine: queries server_ips in order, handles answers, 
    CNAME redirects, glue records, and unglued nameservers.
    """
    for ip in server_ips:
        if ip in visited:
            continue
        visited.add(ip)

        response = send_query(target_name, qtype, ip)
        if response is None:
            continue  # Non-responsive or error: try the next server in the list

        # 1. Directly Answered (Contains records matching query type or CNAME)
        if response.answer:
            return response

        # 2. Extract NS delegations from Authority Section
        ns_names = []
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NS:
                for rdata in rrset:
                    ns_names.append(rdata.target)

        if not ns_names:
            continue

        # 3. Extract Glue Records (IPv4 only) from Additional Section
        glue_ips = []
        for rrset in response.additional:
            if rrset.rdtype == dns.rdatatype.A:
                for rdata in rrset:
                    glue_ips.append(str(rdata))

        # Store intermediate delegations in cache
        name_str = target_name.to_text().lower()
        parts = name_str.rstrip('.').split('.')
        if len(parts) >= 2:
            suffix = ".".join(parts[-2:]) + "."
            if glue_ips:
                DELEGATION_CACHE.setdefault(suffix, []).extend(glue_ips)

        # 4. Use Glue IPs if available
        if glue_ips:
            res = recursive_resolve(target_name, qtype, glue_ips, visited)
            if res and (res.answer or res.rcode() == dns.rcode.NXDOMAIN):
                return res

        # 5. Handle Unglued Nameservers: resolve their A records first
        for ns_name in ns_names:
            ns_response = lookup(ns_name, dns.rdatatype.A)
            ns_ips = []
            if ns_response and ns_response.answer:
                for rrset in ns_response.answer:
                    if rrset.rdtype == dns.rdatatype.A:
                        for rdata in rrset:
                            ns_ips.append(str(rdata))

            if ns_ips:
                res = recursive_resolve(target_name, qtype, ns_ips, visited)
                if res and (res.answer or res.rcode() == dns.rcode.NXDOMAIN):
                    return res

    # If all servers fail, return a blank message instead of crashing
    return dns.message.make_response(dns.message.make_query(target_name, qtype))


def lookup(target_name: dns.name.Name,
           qtype: dns.rdata.Rdata) -> dns.message.Message:
    """
    Recursive DNS lookup entry point with dual-layer caching.
    """
    cache_key = (target_name.to_text().lower(), int(qtype))

    # Requirement: Exact lookup caching
    if cache_key in EXACT_CACHE:
        return EXACT_CACHE[cache_key]

    # Requirement: Intermediate caching (check domain suffixes)
    name_str = target_name.to_text().lower()
    parts = name_str.rstrip('.').split('.')
    initial_servers = []

    for i in range(len(parts)):
        suffix = ".".join(parts[i:]) + "."
        if suffix in DELEGATION_CACHE:
            initial_servers = list(DELEGATION_CACHE[suffix])
            break

    if not initial_servers:
        initial_servers = list(ROOT_SERVERS)

    # Execute recursive resolution
    response = recursive_resolve(target_name, qtype, initial_servers, set())

    # Check for CNAME restarts
    if response and response.answer:
        cname_target = None
        has_direct_answer = False

        for rrset in response.answer:
            if rrset.rdtype == qtype:
                has_direct_answer = True
            elif rrset.rdtype == dns.rdatatype.CNAME:
                cname_target = rrset[0].target

        # If it's a CNAME redirect and we were looking for something else (e.g. A record)
        if not has_direct_answer and cname_target:
            cname_response = lookup(cname_target, qtype)
            # Combine CNAME record with target records into response
            response.answer.extend(cname_response.answer)

    EXACT_CACHE[cache_key] = response
    return response


def collect_results(name: str) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    full_response = {}
    target_name = dns.name.from_text(name)
    # lookup CNAME
    response = lookup(target_name, dns.rdatatype.CNAME)
    cnames = []
    tmp = name
    for answers in response.answer:
        for answer in answers:
            cnames.append({"name": answer, "alias": tmp})
            tmp = answer
    # lookup A
    response = lookup(target_name, dns.rdatatype.A)
    arecords = []
    for answers in response.answer:
        a_name = answers.name
        for answer in answers:
            if answer.rdtype == 1:  # A record
                arecords.append({"name": a_name, "address": str(answer)})
    # lookup AAAA
    response = lookup(target_name, dns.rdatatype.AAAA)
    aaaarecords = []
    for answers in response.answer:
        aaaa_name = answers.name
        for answer in answers:
            if answer.rdtype == 28:  # AAAA record
                aaaarecords.append({"name": aaaa_name, "address": str(answer)})
    # lookup MX
    response = lookup(target_name, dns.rdatatype.MX)
    mxrecords = []
    for answers in response.answer:
        mx_name = answers.name
        for answer in answers:
            if answer.rdtype == 15:  # MX record
                mxrecords.append({"name": mx_name,
                                  "preference": answer.preference,
                                  "exchange": str(answer.exchange)})

    full_response["CNAME"] = cnames
    full_response["A"] = arecords
    full_response["AAAA"] = aaaarecords
    full_response["MX"] = mxrecords

    return full_response


def print_results(results: dict) -> None:
    """
    take the results of a `lookup` and print them to the screen like the host
    program would.
    """
    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


def main():
    """
    if run from the command line, take args and call
    printresults(lookup(hostname))
    """
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()
    for a_domain_name in program_args.name:
        print_results(collect_results(a_domain_name))


if __name__ == "__main__":
    main()
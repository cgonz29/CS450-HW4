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

# Global Caches
EXACT_CACHE = {}       # (name_str, qtype_int) -> dns.message.Message
DELEGATION_CACHE = {}  # zone_suffix_str -> list of IP addresses


def send_query(target_name: dns.name.Name, qtype: dns.rdata.Rdata, server_ip: str):
    """
    Sends a UDP DNS query with a 3-second timeout.
    Catches all exceptions to prevent stack traces.
    """
    try:
        query = dns.message.make_query(target_name, qtype)
        return dns.query.udp(query, server_ip, timeout=3.0)
    except Exception:
        return None


def resolve_domain_with_servers(target_name: dns.name.Name, qtype: dns.rdata.Rdata, servers: list, visited: set) -> dns.message.Message:
    """
    Iterates over available servers for target_name and qtype, recursing down delegations.
    """
    for server_ip in servers:
        if server_ip in visited:
            continue
        visited.add(server_ip)

        response = send_query(target_name, qtype, server_ip)
        if response is None:
            continue

        # 1. Direct Answer
        if response.answer:
            return response

        # Extract NS records from Authority section
        ns_names = []
        ns_zone_name = None
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NS:
                ns_zone_name = rrset.name.to_text().lower()
                for rdata in rrset:
                    ns_names.append(rdata.target)

        if not ns_names:
            continue

        # Extract IPv4 Glue Records from Additional section
        glue_ips = []
        for rrset in response.additional:
            if rrset.rdtype == dns.rdatatype.A:
                for rdata in rrset:
                    glue_ips.append(str(rdata))

        # Cache Delegation IPs for the specific zone declared in Authority
        if ns_zone_name and glue_ips:
            if ns_zone_name not in DELEGATION_CACHE:
                DELEGATION_CACHE[ns_zone_name] = []
            for g_ip in glue_ips:
                if g_ip not in DELEGATION_CACHE[ns_zone_name]:
                    DELEGATION_CACHE[ns_zone_name].append(g_ip)

        # Recurse with Glue IPs if present
        if glue_ips:
            res = resolve_domain_with_servers(target_name, qtype, glue_ips, visited)
            if res and res.answer:
                return res

        # Handle Unglued Nameservers: resolve NS target IP address via recursive lookup
        for ns_name in ns_names:
            ns_msg = lookup(ns_name, dns.rdatatype.A)
            ns_ips = []
            if ns_msg and ns_msg.answer:
                for rrset in ns_msg.answer:
                    if rrset.rdtype == dns.rdatatype.A:
                        for rdata in rrset:
                            ns_ips.append(str(rdata))

            if ns_ips:
                res = resolve_domain_with_servers(target_name, qtype, ns_ips, visited)
                if res and res.answer:
                    return res

    return dns.message.make_response(dns.message.make_query(target_name, qtype))


def lookup(target_name: dns.name.Name,
           qtype: dns.rdata.Rdata) -> dns.message.Message:
    """
    Main recursive DNS lookup entry point supporting exact and intermediate caching.
    """
    name_key = target_name.to_text().lower()
    cache_key = (name_key, int(qtype))

    if cache_key in EXACT_CACHE:
        return EXACT_CACHE[cache_key]

    # Intermediate Caching: Search longest suffix match in DELEGATION_CACHE
    parts = name_key.rstrip('.').split('.')
    initial_servers = []

    for i in range(len(parts)):
        suffix = ".".join(parts[i:]) + "."
        if suffix in DELEGATION_CACHE:
            initial_servers = list(DELEGATION_CACHE[suffix])
            break

    if not initial_servers:
        initial_servers = list(ROOT_SERVERS)

    visited = set()
    response = resolve_domain_with_servers(target_name, qtype, initial_servers, visited)

    # CNAME Restart logic for non-CNAME queries
    if response and response.answer and qtype != dns.rdatatype.CNAME:
        cname_target = None
        has_direct_answer = False

        for rrset in response.answer:
            if rrset.rdtype == qtype:
                has_direct_answer = True
            elif rrset.rdtype == dns.rdatatype.CNAME:
                cname_target = rrset[0].target

        if not has_direct_answer and cname_target:
            # Query target domain for the original record type
            cname_res = lookup(cname_target, qtype)
            if cname_res and cname_res.answer:
                # Combine CNAME answer set with final destination records
                combined = dns.message.make_response(dns.message.make_query(target_name, qtype))
                combined.answer.extend(response.answer)
                combined.answer.extend(cname_res.answer)
                response = combined

    EXACT_CACHE[cache_key] = response
    return response


def collect_results(name: str) -> dict:
    """
    Parses final answers into the proper structure expected by print_results.
    """
    full_response = {}
    target_name = dns.name.from_text(name)
    
    # lookup CNAME
    response = lookup(target_name, dns.rdatatype.CNAME)
    cnames = []
    tmp = name
    for answers in response.answer:
        for answer in answers:
            if answer.rdtype == dns.rdatatype.CNAME:
                cnames.append({"name": str(answer.target), "alias": tmp})
                tmp = str(answer.target)

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
    Prints results to stdout matching the host utility format.
    """
    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


def main():
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
import argparse
import signal
import sys
import time
import yaml
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, QTYPE, RCODE, A, AAAA, CNAME, MX, NS, SOA, TXT, DNSLabel
from dnslib.server import DNSServer, BaseResolver, DNSLogger

class Resolver(BaseResolver):
    def __init__(self, zone, recursion_available=False):
        self.zone = zone
        self.ra = recursion_available

    def resolve(self, request, handler):
        qname = request.q.qname
        qtype = request.q.qtype
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=int(self.ra)), q=DNSQuestion(qname, qtype))

        answers = self.zone.get_records(qname, qtype)
        if answers:
            for rr in answers:
                reply.add_answer(rr)
        else:
            reply.header.rcode = RCODE.NXDOMAIN
            for rr in self.zone.get_records(self.zone.origin, QTYPE.SOA):
                reply.add_auth(rr)
        return reply

class Zone:
    def __init__(self, config):
        self.origin = DNSLabel(config["zone"]["origin"])
        self.ttl = int(config["zone"].get("default_ttl", 300))
        self.records = {}
        self.build_records(config)

    def add_record(self, name, rtype, value, ttl):
        t = getattr(QTYPE, rtype, None)
        if t is None:
            print(f"[WARN] Неизвестный тип записи: {rtype}")
            return

        rname = DNSLabel(name)
        rr = None

        if rtype == "A":
            rr = RR(rname, QTYPE.A, rdata=A(value), ttl=ttl)
        elif rtype == "AAAA":
            rr = RR(rname, QTYPE.AAAA, rdata=AAAA(value), ttl=ttl)
        elif rtype == "CNAME":
            rr = RR(rname, QTYPE.CNAME, rdata=CNAME(DNSLabel(value)), ttl=ttl)
        elif rtype == "MX":
            try:
                prio, host = value.strip().split(maxsplit=1)
                rr = RR(rname, QTYPE.MX, rdata=MX(int(prio), DNSLabel(host)), ttl=ttl)
            except Exception as e:
                print(f"[WARN] Ошибка разбора MX записи '{value}': {e}")
        elif rtype == "TXT":
            rr = RR(rname, QTYPE.TXT, rdata=TXT(value), ttl=ttl)
        elif rtype == "NS":
            rr = RR(rname, QTYPE.NS, rdata=NS(DNSLabel(value)), ttl=ttl)
        elif rtype == "SOA":
            # SOA отдельно в build_records()
            return
        else:
            print(f"[WARN] Тип {rtype} не реализован")
            return

        if rr:
            self.records.setdefault((rname, t), []).append(rr)

    def build_records(self, config):
        zone = config["zone"]
        soa = zone["soa"]
        serial = int(time.strftime("%Y%m%d%H")) if soa.get("serial") == "auto" else int(soa["serial"])
        soa_rr = SOA(
            mname=DNSLabel(soa["mname"]),
            rname=DNSLabel(soa["rname"]),
            times=(serial, soa["refresh"], soa["retry"], soa["expire"], soa["minimum"])
        )
        self.records[(self.origin, QTYPE.SOA)] = [RR(self.origin, QTYPE.SOA, rdata=soa_rr, ttl=self.ttl)]
        ns_records = [RR(self.origin, QTYPE.NS, rdata=NS(DNSLabel(ns)), ttl=self.ttl) for ns in zone.get("ns", [])]
        self.records[(self.origin, QTYPE.NS)] = ns_records

        for rec in config.get("records", []):
            self.add_record(rec["name"], rec["type"].upper(), rec["value"], rec.get("ttl", self.ttl))

    def get_records(self, name, qtype):
        return self.records.get((name, qtype), [])

def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def main():
    parser = argparse.ArgumentParser(description="Простой DNS-сервер (A, AAAA, CNAME, MX, TXT, NS, SOA)")
    parser.add_argument("-c", "--config", default="config.yaml", help="Путь к конфигурационному файлу")
    args = parser.parse_args()

    config = load_config(args.config)
    zone = Zone(config)

    logger = DNSLogger("request,reply,error" if config["server"].get("verbose", True) else "error")
    resolver = Resolver(zone)

    udp_server = DNSServer(resolver, port=config["server"]["udp_port"], address=config["server"]["listen_host"], logger=logger)
    tcp_server = DNSServer(resolver, port=config["server"]["tcp_port"], address=config["server"]["listen_host"], tcp=True, logger=logger)

    def stop(sig, frame):
        print("\nОстановка сервера...")
        udp_server.stop()
        tcp_server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    udp_server.start_thread()
    tcp_server.start_thread()

    print(f"DNS сервер запущен на {config['server']['listen_host']}:{config['server']['udp_port']} (UDP/TCP)")
    print(f"Обслуживает зону: {zone.origin}")

    while udp_server.isAlive() and tcp_server.isAlive():
        time.sleep(1)

if __name__ == "__main__":
    main()

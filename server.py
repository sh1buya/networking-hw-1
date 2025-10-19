import argparse, os, signal, sys, time, yaml
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, QTYPE, RCODE, A, AAAA, CNAME, NS, SOA, TXT, DNSLabel
from dnslib.server import DNSServer, BaseResolver

class Resolver(BaseResolver):
    def __init__(self, zone, recursion_available=False):
        self.zone = zone
        self.ra = recursion_available

    def resolve(self, request, handler):
        qname = request.q.qname
        qtype = request.q.qtype

        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=int(self.ra)),
            q=DNSQuestion(qname, qtype)
        )

        answers = self.zone.get_records(qname, qtype)
        if answers:
            for rr in answers:
                reply.add_answer(rr)
            for rr in self.zone.get_records(self.zone.origin, QTYPE.NS):
                reply.add_auth(rr)
        else:
            has_name = self.zone.name_exists(qname)
            reply.header.rcode = RCODE.NOERROR if has_name else RCODE.NXDOMAIN
            soa = self.zone.get_records(self.zone.origin, QTYPE.SOA)
            if soa:
                for rr in soa: reply.add_auth(rr)
            else:
                for rr in self.zone.get_records(self.zone.origin, QTYPE.NS):
                    reply.add_auth(rr)
        return reply

class Zone:
    def __init__(self, config):
        z = config["zone"]
        self.origin = DNSLabel(z["origin"])
        self.ttl = int(z.get("default_ttl", 300))
        self.records = {}
        self.build_records(config)

    def _add(self, name, tcode, rdata, ttl):
        rname = DNSLabel(str(name))
        self.records.setdefault((rname, tcode), []).append(RR(rname, tcode, rdata=rdata, ttl=int(ttl)))

    def add_record(self, name, rtype, value, ttl):
        rtype = str(rtype).upper().strip()
        t = getattr(QTYPE, rtype, None)
        if t is None:
            print(f"[INFO] Пропущен неизвестный тип: {rtype}")
            return

        try:
            if rtype == "A":
                self._add(name, QTYPE.A, A(str(value)), ttl)
            elif rtype == "AAAA":
                self._add(name, QTYPE.AAAA, AAAA(str(value)), ttl)
            elif rtype == "CNAME":
                self._add(name, QTYPE.CNAME, CNAME(DNSLabel(str(value))), ttl)
            elif rtype == "TXT":
                self._add(name, QTYPE.TXT, TXT(str(value)), ttl)
            elif rtype == "NS":
                self._add(name, QTYPE.NS, NS(DNSLabel(str(value))), ttl)
            elif rtype == "SOA":
                return
            else:
                print(f"[INFO] Пропущен неиспользуемый тип: {rtype}")
        except Exception as e:
            print(f"[WARN] Ошибка при добавлении {rtype} {name} value={value!r}: {e}")

    def build_records(self, config):
        z = config["zone"]

        soa = z.get("soa")
        if soa:
            serial = int(time.strftime("%Y%m%d%H")) if str(soa.get("serial","auto")) == "auto" else int(soa["serial"])
            self._add(
                z["origin"], QTYPE.SOA,
                SOA(DNSLabel(soa["mname"]), DNSLabel(soa["rname"]),
                    (serial, int(soa["refresh"]), int(soa["retry"]), int(soa["expire"]), int(soa["minimum"]))),
                self.ttl
            )

        for ns in z.get("ns", []):
            self._add(z["origin"], QTYPE.NS, NS(DNSLabel(ns)), self.ttl)

        for rec in config.get("records", []):
            self.add_record(rec["name"], rec["type"], rec["value"], rec.get("ttl", self.ttl))

    def get_records(self, name, qtype):
        return self.records.get((name, qtype), [])

    def name_exists(self, name):
        for (n, _t) in self.records.keys():
            if n == name:
                return True
        return False

def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def main():
    parser = argparse.ArgumentParser(description="Простой DNS-сервер (A, AAAA, CNAME, TXT, NS, SOA)")
    parser.add_argument("-c", "--config", default="config.yaml", help="Путь к конфигурационному файлу")
    args = parser.parse_args()

    config_path = os.path.abspath(args.config)
    print("USING CONFIG:", config_path)
    config = load_config(config_path)

    zone = Zone(config)
    resolver = Resolver(zone)

    addr = config["server"].get("listen_host", "0.0.0.0")
    udp_port = int(config["server"].get("udp_port", 5300))
    tcp_port = int(config["server"].get("tcp_port", udp_port))

    udp_server = DNSServer(resolver, port=udp_port, address=addr)
    tcp_server = DNSServer(resolver, port=tcp_port, address=addr, tcp=True)

    def stop(_sig, _frame):
        print("\nОстановка сервера...")
        udp_server.stop(); tcp_server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    udp_server.start_thread()
    tcp_server.start_thread()

    print(f"DNS сервер запущен на {addr}:{udp_port} (UDP/TCP)")
    print(f"Обслуживает зону: {zone.origin}")

    try:
        while udp_server.isAlive() and tcp_server.isAlive():
            time.sleep(1)
    except KeyboardInterrupt:
        stop(None, None)

if __name__ == "__main__":
    main()

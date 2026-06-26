# Java DPI Engine

Dependency-free Java port of the packet analyzer. It reads a PCAP file, parses
Ethernet/IPv4/TCP/UDP packets, extracts TLS SNI or HTTP Host values, classifies
traffic by application, applies blocking rules, and writes a filtered PCAP.

The runtime pipeline uses 2 load balancers and 4 fast-path processors:

```text
PCAP Reader -> 2 LoadBalancers -> 4 FP Threads -> Ordered PCAP Writer
```

Each packet flow is hashed to one load balancer and then one FP thread, so
packets from the same connection keep one worker-owned flow state.

## Project Layout

```text
Packet_analyzer/
├── src/main/java/com/packetanalyzer/dpi/   Java source
├── build-java.sh                           Java build script
├── test_dpi.pcap                           Sample input PCAP
├── output.pcap                             Existing sample/output PCAP
└── generate_test_pcap.py                   Test PCAP generator
```

## Build

```bash
./build-java.sh
```

The runnable jar is generated at:

```text
build/dpi-engine.jar
```

## Run

```bash
java -jar build/dpi-engine.jar test_dpi.pcap filtered.pcap
```

With blocking rules:

```bash
java -jar build/dpi-engine.jar test_dpi.pcap filtered.pcap --block-app YouTube
java -jar build/dpi-engine.jar test_dpi.pcap filtered.pcap --block-ip 192.168.1.50
java -jar build/dpi-engine.jar test_dpi.pcap filtered.pcap --block-domain youtube.com
```

Supported options:

```text
--block-ip <ip>        Block traffic from a source IP
--block-app <app>      Block an application such as YouTube, Facebook, GitHub
--block-domain <dom>   Block domains by substring match
```

## React Dashboard

The React frontend lives in `frontend/`. It provides a dashboard with detected
applications/websites, click-to-block app selection, traffic summary cards, and
a detailed result table showing blocked versus allowed traffic.

Start the Java API first:

```bash
./build-java.sh
java -cp build/dpi-engine.jar com.packetanalyzer.dpi.DashboardServer
```

The API runs at:

```text
http://127.0.0.1:8080
```

Then start the frontend:

```bash
cd frontend
npm install
npm run dev
```

Then open the local URL printed by Vite. The dashboard calls
`POST /api/analyze` and sends selected blocked apps plus derived domains and
source IPs to the Java backend, so app clicks apply app, domain, and source-IP
rules together. Use the upload button in the top bar to choose a `.pcap` file.
The frontend sends it to `POST /api/upload`, and the Java backend saves it
under `build/uploads/` before running analysis on the uploaded capture.

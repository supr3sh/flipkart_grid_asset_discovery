# Flipkart GRID : Asset Discovery tool

* To print usage:
```
python3 asset_discovery.py -h
```

* To scan an IP or a URL:
```
python3 asset_discovery.py --ip <ip-address>
python3 asset_discovery.py --url <url>
```
* To scan a local network
```
python3 asset_discovery.py --local --range <network-range>
```

* To scan a remote network( via SSH tunneling and proxychains)
```
python3 asset_discovery.py --remote --range <network-range>
```

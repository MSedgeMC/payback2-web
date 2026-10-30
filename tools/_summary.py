import sys, json
for line in sys.stdin:
    data = json.loads(line)
    name = data["path"].split("/")[-1]
    print(f'{name}: {data["supported"]}/{data["code"]} = {data["percent"]}% of executable words')
    open(".local/unsupported-" + name + ".json", "w").write(json.dumps(data["unsupportedAddresses"]))

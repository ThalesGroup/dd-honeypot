### Send data to S3 using fluent-bit
Fluent-bit is a light weight data collector and log processor. It can be used to send data to S3.
First you have to create a bucket in S3, and then create a configuration file for fluent-bit. The configuration file should look like this:
```ini
[SERVICE]
    Parsers_File parsers.conf

[INPUT]
    Name         forward
    Listen       0.0.0.0
    Port         24224

[FILTER]
    Name         grep
    Match        docker.*
    Regex        log    ^\{\"dd-honeypot\":\s*true

[OUTPUT]
    Name              s3
    Match             *
    bucket            your-bucket-name
    region            us-east-1
    store_dir         /tmp/fluentbit/s3
    total_file_size   1M
    upload_timeout    30m
    use_put_object    Off
    s3_key_format     /logs/day=%Y-%m-%d/hour=%H/data-%H-%M-%S.log.jsonl.gz
    compression       gzip
    log_key           log
    static_file_path  On
```
The configuration file should be saved in `/etc/fluent-bit/fluent-bit.conf` on the host machine. Hourly folders will be created, with commands sends to the honeypot in JSON format. The files will be compressed using gzip.

```sh
# run fluent-bit
docker run -d --name fluent-bit \
  -v /var/lib/docker/containers:/var/lib/docker/containers:ro \
  -v /etc/fluent-bit/fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf:ro \
  -v /etc/fluent-bit/log:/var/log \
  -v /tmp/fluentbit:/tmp/fluentbit \
  -p 24224:24224 \
  fluent/fluent-bit

# run the honeypot
docker run --pull=always -d --name dd-honeypot \
  -v /your/honeypot/folder:/data/honeypot \
  -p 80:80 -p 2222:2222 -p 3306:3306 \
  --log-driver=fluentd --log-opt fluentd-address=127.0.0.1:24224 \
  ghcr.io/thalesgroup/dd-honeypot
```
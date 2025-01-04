# Running on AWS EC2

Running on an EC2 instance, and having it push to a local CRC exporter

On the local machine and on ec2:

```shell
$ sudo tailscale up
```

Add an entry to `/etc/hosts` using the output of `tailscale ip`:

```
100.100.100.100   otel-collector.tailscale.local
```

Use `otel-collector.tailscale.local` as the host of the otel http route:

```
kind: Route
apiVersion: route.openshift.io/v1
metadata:
  name: otel-http
  namespace: lgtm

spec:
  host: otel-collector.tailscale.local
  to:
    kind: Service
    name: lgtm
    weight: 100
  port:
    targetPort: otel-http
  wildcardPolicy: None
```

Adjust `config.yaml` to use the new route:

```yaml
receivers:
  dlt:
    daemon_address: "localhost"
    daemon_port: 3490

processors:
  batch:
    timeout: 1s
    send_batch_size: 1024
  filter:
    error_mode: ignore
    logs:
      log_record:
        - 'not IsMatch(body, ".*test.*")'

exporters:
  debug:
    verbosity: detailed
  otlphttp:
    endpoint: "http://otel-collector.tailscale.local:4318"
    tls:
      insecure: true

service:
  pipelines:
    logs:
      receivers: [dlt]
      processors: [batch,filter]
      exporters: [debug,otlphttp]
```

Run port forward on the local machine:

```shell
$ oc port-forward svc/lgtm -n lgtm 4318:4318 --address=0.0.0.0
```

Run the otel collector on the ec2 instance:

```shell
$ ./dltreceiver --config config.yaml
```

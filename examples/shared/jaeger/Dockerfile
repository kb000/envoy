FROM jaegertracing/all-in-one@sha256:402d5b966971ab4504264804a1f4bd90926ffbc08b9f7fb110215701d6197ede
HEALTHCHECK \
    --interval=1s \
    --timeout=1s \
    --start-period=1s \
    --retries=60 \
    CMD wget -q --header='Content-Type:application/json' -O - http://localhost:14269/health | grep "Server available"

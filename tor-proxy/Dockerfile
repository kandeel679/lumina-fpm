FROM alpine:latest
RUN apk add --no-cache tor obfs4proxy
COPY torrc /etc/tor/torrc
RUN chown -R tor /etc/tor
USER tor
CMD ["tor", "-f", "/etc/tor/torrc"]

FROM alpine:latest as certs
RUN apk --update add ca-certificates

FROM scratch
ADD contactform-slack /
ADD GeoLite2-City.mmdb /
ADD localhost.key /
ADD localhost.pem /
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

EXPOSE 8080
CMD ["/contactform-slack"]

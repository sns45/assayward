FROM gcr.io/distroless/static:nonroot

COPY assayward /assayward

ENTRYPOINT ["/assayward"]

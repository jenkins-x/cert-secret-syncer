FROM gcr.io/distroless/static:nonroot
ENTRYPOINT ["/cert-secret-syncer"]
COPY ./build/linux/ /

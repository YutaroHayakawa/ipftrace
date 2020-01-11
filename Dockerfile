FROM fedora:30
RUN dnf install -y python3 bcc && dnf clean all
ADD ./ /ipftrace/
ENV PYTHONUNBUFFERED=1
RUN cd /ipftrace && pip3 install -e .
ENTRYPOINT ["ipftrace"]
